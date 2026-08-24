// Package basic provides username/password authentication with secure password
// hashing.
//
// # What the credential store receives
//
// Nothing this package hands to storage.CredentialStore can be replayed against
// it. Passwords arrive as bcrypt digests, and password-reset and
// email-verification tokens arrive as SHA-256 digests of the value that was
// emailed (finding F-05, CWE-522). The plaintext token is returned to the caller
// exactly once, so it can be placed in a link; the library keeps no copy of it.
//
// Equality is therefore decided by the store's lookup of the digest, not by any
// comparison this package performs. That is why there is no crypto/subtle call
// on the token paths: what the store compares is a digest of a 256-bit
// crypto/rand value, and the digest is not a preimage anyone can work back from.
// A store that indexes the column and compares it with SQL equality is correct.
//
// # Multi-factor authentication
//
// Authenticate refuses a password-only sign-in for a user who holds a confirmed
// TOTP factor, returning ErrMFARequired (see MFAEnforcement). Before this change
// the factor was only consulted by AuthenticateWithTOTP, so a call site that
// used the wrong method silently bypassed it.
//
// # What this package cannot revoke
//
// Changing a password ends nothing. This library does not own the caller's
// sessions or refresh tokens, and storage.SessionStore has no bulk-delete method
// in v1 (finding F-13, CWE-613). ChangePassword, ResetPassword and
// CompletePasswordReset each document the revocation the caller must perform.
package basic

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/meysam81/go-auth/auth/totp"
	"github.com/meysam81/go-auth/storage"
	"golang.org/x/crypto/bcrypt"
)

var (
	// ErrInvalidCredentials is returned when authentication fails.
	//
	// It is returned for an unknown identifier, a user with no password
	// credential and a wrong password alike, and all three cost the same bcrypt
	// evaluation, so neither the error nor the latency reports whether the
	// account exists (finding F-09, CWE-208).
	ErrInvalidCredentials = errors.New("invalid credentials")

	// ErrUserExists is returned when attempting to register a user that already exists.
	ErrUserExists = errors.New("user already exists")

	// ErrWeakPassword is returned when a password doesn't meet minimum requirements.
	ErrWeakPassword = errors.New("password does not meet minimum requirements")

	// ErrPasswordTooLong is returned when a password exceeds MaxPasswordLength
	// bytes.
	//
	// bcrypt ignores everything past its 72-byte limit, so accepting a longer
	// password authenticates the user by a prefix of it and makes two distinct
	// passphrases sharing that prefix interchangeable (finding F-10, CWE-916).
	// Truncating silently is the defect; refusing is the fix.
	ErrPasswordTooLong = errors.New("password exceeds maximum length")

	// ErrPasswordContainsNUL is returned when a password contains a NUL byte.
	//
	// Go's bcrypt hashes the whole byte slice, but the C implementations a
	// deployment may later migrate to treat NUL as a string terminator. The same
	// stored digest would then verify against the prefix alone, so the byte is
	// refused at the door rather than left to change meaning under a future
	// verifier (finding F-10, CWE-916).
	ErrPasswordContainsNUL = errors.New("password contains a NUL byte")

	// ErrEmailNotVerified is returned when a user attempts to authenticate without verifying their email.
	ErrEmailNotVerified = errors.New("email not verified")

	// ErrInvalidToken is returned when a token is invalid or expired.
	ErrInvalidToken = errors.New("invalid or expired token")

	// ErrUserNotFound is returned when an operation names a user that does not
	// exist. It is used only on paths where the caller already knows the user --
	// never on a sign-in or reset path, where reporting existence is the
	// enumeration oracle of finding F-09.
	ErrUserNotFound = errors.New("user not found")

	// ErrEmailAlreadyVerified is returned when a verification token is requested
	// for an address that is already verified.
	ErrEmailAlreadyVerified = errors.New("email already verified")

	// ErrMFARequired is returned by Authenticate when the password was correct but
	// the user holds a confirmed second factor and MFAEnforcement is EnforceMFA.
	//
	// It is not an authentication failure: the caller has verified the first
	// factor and must now collect a code and call AuthenticateWithTOTP. Treating
	// it as a failed sign-in is what turns the MFA prompt into an MFA bypass.
	ErrMFARequired = errors.New("multi-factor authentication required")

	// ErrRegistrationRollbackFailed is returned when Register could not store the
	// password AND could not remove the user row it had already created.
	//
	// The account exists with no credential: it cannot authenticate, and the
	// duplicate check at the top of Register blocks the address from being
	// registered again, so the user is locked out of their own email with no
	// self-service path (finding F-11, CWE-460). The wrapped error names the user
	// ID that must be removed out of band.
	ErrRegistrationRollbackFailed = errors.New("registration rollback failed: user exists without a credential")

	// ErrResetTokenNotRevoked is returned when CompletePasswordReset changed the
	// password but could not delete the reset token.
	//
	// The password change SUCCEEDED. The token stays usable until its TTL expires,
	// so the same link resets the password a second time (finding F-12, CWE-613).
	// A caller must not retry the reset; it must invalidate the token by another
	// route, or accept the exposure for at most Config.PasswordResetTTL.
	ErrResetTokenNotRevoked = errors.New("password changed but reset token could not be revoked")

	// ErrVerificationTokenNotRevoked is returned when VerifyEmail marked the
	// address verified but could not delete the verification token. The
	// verification SUCCEEDED; the token stays usable until its TTL expires.
	ErrVerificationTokenNotRevoked = errors.New("email verified but verification token could not be revoked")

	// ErrTOTPNotConfigured is returned by the TOTP convenience methods when the
	// authenticator was built without Config.TOTPManager.
	ErrTOTPNotConfigured = errors.New("TOTP manager not configured")
)

const (
	// MinPasswordLength is the minimum required password length, in bytes.
	MinPasswordLength = 8

	// MaxPasswordLength is the maximum accepted password length, in BYTES.
	//
	// It is bcrypt's own limit, not a policy choice, and it is a byte count
	// because bcrypt operates on the UTF-8 encoding: a 30-character CJK
	// passphrase is 90 bytes and exceeds the limit its character count does not
	// suggest (finding F-10, CWE-916).
	MaxPasswordLength = 72

	// DefaultBcryptCost is the default bcrypt cost factor.
	DefaultBcryptCost = 12

	// DefaultPasswordResetTTL is the default password reset token TTL.
	DefaultPasswordResetTTL = 1 * time.Hour

	// DefaultEmailVerificationTTL is the default email verification token TTL.
	DefaultEmailVerificationTTL = 24 * time.Hour
)

// timingEqualizationInput is the fixed plaintext hashed once per Authenticator
// and compared against on every not-found path, so that an unknown identifier
// costs the same bcrypt evaluation as a known one (finding F-09, CWE-208). Its
// value is irrelevant and deliberately not password-shaped: nothing authenticates
// with it, because the paths that use it return ErrInvalidCredentials regardless
// of the comparison's outcome.
const timingEqualizationInput = "go-auth fixed input for constant-cost sign-in"

// MFAEnforcement selects what Authenticate does once it has verified the password
// of a user who also holds a confirmed second factor.
//
// The zero value is EnforceMFA, so a caller that does not set
// Config.RequireMFAWhenEnrolled gets the safe behavior.
type MFAEnforcement int

const (
	// EnforceMFA makes Authenticate return ErrMFARequired for a user with a
	// confirmed second factor, instead of returning the user. It is the zero
	// value of MFAEnforcement.
	//
	// A TOTP enrollment still awaiting totp.Manager.Confirm does not count: it has
	// never validated a code, so gating sign-in on it would lock the user out of
	// their own half-finished enrollment (finding F-07).
	EnforceMFA MFAEnforcement = iota

	// AllowPasswordOnly restores the pre-hardening behavior: Authenticate returns
	// the user on the password alone even when a confirmed second factor exists.
	//
	// It exists for a deployment whose sign-in handler calls Authenticate and then
	// performs its own second-factor step, and whose flow would break on
	// ErrMFARequired. Any other use is an MFA bypass: the factor is enrolled, the
	// user believes it protects them, and one call site decides it does not.
	//
	// Deprecated: this is a migration shim for the MFA-bypass fix and v2 removes
	// it. Move the call site to AuthenticateWithTOTP and leave this unset.
	AllowPasswordOnly
)

// Authenticator handles basic username/password authentication.
type Authenticator struct {
	userStore                storage.UserStore
	credentialStore          storage.CredentialStore
	bcryptCost               int
	requireEmailVerification bool
	passwordResetTTL         time.Duration
	emailVerificationTTL     time.Duration
	totpManager              *totp.Manager
	mfaEnforcement           MFAEnforcement

	// dummyHash is a bcrypt digest at bcryptCost, minted once in NewAuthenticator.
	// See timingEqualizationInput.
	dummyHash []byte
}

// Config configures the basic authenticator.
type Config struct {
	UserStore                storage.UserStore
	CredentialStore          storage.CredentialStore
	BcryptCost               int           // Optional: defaults to DefaultBcryptCost
	RequireEmailVerification bool          // Optional: defaults to false
	PasswordResetTTL         time.Duration // Optional: defaults to DefaultPasswordResetTTL
	EmailVerificationTTL     time.Duration // Optional: defaults to DefaultEmailVerificationTTL
	TOTPManager              *totp.Manager // Optional: if provided, enables TOTP support

	// RequireMFAWhenEnrolled decides whether Authenticate refuses a password-only
	// sign-in for a user holding a confirmed second factor. The zero value,
	// EnforceMFA, refuses it.
	//
	// Migration: a caller that previously relied on Authenticate succeeding on the
	// password alone, and then ran its own TOTP step, now sees ErrMFARequired.
	// Either switch that call site to AuthenticateWithTOTP, which performs both
	// factors in one call, or set this to AllowPasswordOnly and keep the existing
	// flow. Handling ErrMFARequired as a failed sign-in silently locks out every
	// enrolled user, so it must be handled explicitly either way.
	RequireMFAWhenEnrolled MFAEnforcement
}

// NewAuthenticator creates a new basic authenticator.
//
// It performs one bcrypt evaluation at the configured cost to mint the fixed
// digest that equalizes the account-not-found path (finding F-09), so
// construction costs roughly what a sign-in costs. Build the Authenticator once
// at startup, not per request.
func NewAuthenticator(cfg Config) (*Authenticator, error) {
	if cfg.UserStore == nil {
		return nil, errors.New("user store is required")
	}
	if cfg.CredentialStore == nil {
		return nil, errors.New("credential store is required")
	}

	cost := cfg.BcryptCost
	if cost == 0 {
		cost = DefaultBcryptCost
	}
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return nil, fmt.Errorf("bcrypt cost must be between %d and %d", bcrypt.MinCost, bcrypt.MaxCost)
	}

	switch cfg.RequireMFAWhenEnrolled {
	case EnforceMFA, AllowPasswordOnly:
	default:
		// Fail at startup rather than at the first sign-in: an out-of-range value
		// here decides whether a second factor is enforced, and the safe reading of
		// a value nobody defined is that the deployment is misconfigured.
		return nil, fmt.Errorf("unknown MFA enforcement value %d", cfg.RequireMFAWhenEnrolled)
	}

	passwordResetTTL := cfg.PasswordResetTTL
	if passwordResetTTL == 0 {
		passwordResetTTL = DefaultPasswordResetTTL
	}

	emailVerificationTTL := cfg.EmailVerificationTTL
	if emailVerificationTTL == 0 {
		emailVerificationTTL = DefaultEmailVerificationTTL
	}

	dummyHash, err := bcrypt.GenerateFromPassword([]byte(timingEqualizationInput), cost)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare timing equalization hash: %w", err)
	}

	return &Authenticator{
		userStore:                cfg.UserStore,
		credentialStore:          cfg.CredentialStore,
		bcryptCost:               cost,
		requireEmailVerification: cfg.RequireEmailVerification,
		passwordResetTTL:         passwordResetTTL,
		emailVerificationTTL:     emailVerificationTTL,
		totpManager:              cfg.TOTPManager,
		mfaEnforcement:           cfg.RequireMFAWhenEnrolled,
		dummyHash:                dummyHash,
	}, nil
}

// RegisterRequest contains user registration information.
type RegisterRequest struct {
	Email    string                 `json:"email"`
	Username string                 `json:"username,omitempty"`
	Password string                 `json:"password"`
	Name     string                 `json:"name,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Register creates a new user account with the provided credentials.
//
// It is two store writes -- the user row, then the password hash -- and the
// library cannot make them atomic across two interfaces. If the second fails the
// first is rolled back; if the rollback also fails the error wraps
// ErrRegistrationRollbackFailed and names the orphaned user ID (finding F-11,
// CWE-460).
//
// A store that backs both storage.UserStore and storage.CredentialStore with the
// same database should implement them transactionally, which removes the failure
// mode rather than reporting it.
//
// Deprecated: minting an identifier and writing a user row is the application's
// decision, not a primitive's, and v2 drops storage.UserStore from this package
// (docs/security-hardening.md section 4.1). v1 offers no replacement -- this
// marker is advance notice, not a request to migrate today. In v2 the
// application creates its own user record and asks this package only to hash the
// password and verify it.
func (a *Authenticator) Register(ctx context.Context, req RegisterRequest) (*storage.User, error) {
	// Validate password strength
	if err := a.validatePassword(req.Password); err != nil {
		return nil, err
	}

	// Check if user already exists by email
	if req.Email != "" {
		if _, err := a.userStore.GetUserByEmail(ctx, req.Email); err == nil {
			return nil, ErrUserExists
		} else if !errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("failed to check existing user: %w", err)
		}
	}

	// Check if username is taken
	if req.Username != "" {
		if _, err := a.userStore.GetUserByUsername(ctx, req.Username); err == nil {
			return nil, ErrUserExists
		} else if !errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("failed to check existing username: %w", err)
		}
	}

	// Generate user ID
	userID, err := generateID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate user ID: %w", err)
	}

	// Hash password
	hash, err := a.hashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user := &storage.User{
		ID:       userID,
		Email:    req.Email,
		Username: req.Username,
		Name:     req.Name,
		Provider: "basic",
		Metadata: req.Metadata,
	}

	if err := a.userStore.CreateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	if err := a.credentialStore.StorePasswordHash(ctx, user.ID, hash); err != nil {
		if rollbackErr := a.userStore.DeleteUser(ctx, user.ID); rollbackErr != nil {
			// Both halves are reported: the caller needs the cause to decide whether
			// to retry, and the operator needs the user ID to clean up the row that
			// now blocks re-registration of this address.
			return nil, fmt.Errorf("%w (user id %q): store password: %w; rollback: %w",
				ErrRegistrationRollbackFailed, user.ID, err, rollbackErr)
		}
		return nil, fmt.Errorf("failed to store password: %w", err)
	}

	return user, nil
}

// Authenticate verifies user credentials and returns the user if valid.
// The identifier can be either email or username.
//
// It returns ErrMFARequired when the password is correct but the user holds a
// confirmed second factor and Config.RequireMFAWhenEnrolled is EnforceMFA (the
// default). That is not a failed sign-in: collect a code and call
// AuthenticateWithTOTP.
//
// Every rejection path performs one bcrypt evaluation at the configured cost, so
// an unknown identifier is not distinguishable from a wrong password by latency
// (finding F-09, CWE-208).
//
// Passwords longer than MaxPasswordLength are NOT refused here. bcrypt ignores
// the excess, so a credential registered before the F-10 fix still verifies; the
// limit is enforced where a password is set, not where one is checked.
func (a *Authenticator) Authenticate(ctx context.Context, identifier, password string) (*storage.User, error) {
	user, err := a.authenticatePassword(ctx, identifier, password)
	if err != nil {
		return nil, err
	}

	// Compared against AllowPasswordOnly rather than for EnforceMFA so that any
	// value other than the explicit opt-out enforces the factor.
	if a.mfaEnforcement != AllowPasswordOnly {
		enrolled, err := a.IsTOTPEnabled(ctx, user.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to check second factor: %w", err)
		}
		if enrolled {
			return nil, ErrMFARequired
		}
	}

	return user, nil
}

// authenticatePassword verifies the first factor only. It is what Authenticate
// and AuthenticateWithTOTP share: the MFA gate lives in Authenticate, so
// AuthenticateWithTOTP -- which goes on to prove the second factor itself -- does
// not trip over it.
func (a *Authenticator) authenticatePassword(ctx context.Context, identifier, password string) (*storage.User, error) {
	user, err := a.findUser(ctx, identifier)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, a.compareDummyHash(password)
		}
		return nil, err
	}

	hash, err := a.credentialStore.GetPasswordHash(ctx, user.ID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			// A user row with no password credential -- an SSO account, or the
			// orphan of a failed Register (F-11). Same cost, same error as an
			// unknown identifier.
			return nil, a.compareDummyHash(password)
		}
		return nil, fmt.Errorf("failed to get password hash: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword(hash, []byte(password)); err != nil {
		if !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			// A digest that does not parse is a broken row, not a wrong password.
			// Reporting it as ErrInvalidCredentials makes a corrupted credential
			// look like user error forever, and the user can never sign in again.
			return nil, fmt.Errorf("failed to verify password: %w", err)
		}
		return nil, ErrInvalidCredentials
	}

	// Checked after the password on purpose: "this address exists but is
	// unverified" is a fact about an account, and it is now only disclosed to
	// somebody who has already proved they hold its credential.
	if a.requireEmailVerification && user.Provider == "basic" && !user.EmailVerified {
		return nil, ErrEmailNotVerified
	}

	return user, nil
}

// findUser resolves an identifier that may be either an email address or a
// username. It returns storage.ErrNotFound, unwrapped, when neither matches, so
// callers can decide for themselves whether that fact may be disclosed.
func (a *Authenticator) findUser(ctx context.Context, identifier string) (*storage.User, error) {
	user, err := a.userStore.GetUserByEmail(ctx, identifier)
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	user, err = a.userStore.GetUserByUsername(ctx, identifier)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	return user, nil
}

// compareDummyHash performs the bcrypt evaluation that a not-found path would
// otherwise skip, so that path costs what a real verification costs (finding
// F-09, CWE-208). The comparison's own verdict is meaningless -- there is no
// account behind it -- so ErrInvalidCredentials is returned either way.
//
// The result is still inspected rather than discarded: the only errors possible
// from a digest minted in NewAuthenticator are a mismatch (expected, and the
// whole point) and a malformed digest, which would mean the equalization is not
// happening at all and the timing oracle is quietly back.
func (a *Authenticator) compareDummyHash(password string) error {
	err := bcrypt.CompareHashAndPassword(a.dummyHash, []byte(password))
	if err == nil || errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return ErrInvalidCredentials
	}
	return fmt.Errorf("timing equalization compare failed: %w", err)
}

// ChangePassword changes a user's password.
//
// Revocation is the caller's (finding F-13, CWE-613). A password change is
// usually a response to a suspected compromise, and this library owns neither the
// sessions nor the tokens that must die with the old password. After this returns
// nil the caller MUST:
//
//   - revoke every refresh token for the user, via
//     storage.TokenStore.RevokeAllUserTokens;
//   - delete every session for the user. storage.SessionStore has no bulk delete
//     in v1, so the caller needs its own user-to-session index and a
//     session.Manager.Delete per entry. If the user is changing their own
//     password in an active session, session.Manager.Rotate that one instead of
//     deleting it, so the request that changed the password does not sign itself
//     out (finding F-14, CWE-384).
//
// v2 adds storage.SessionStore.DeleteAllForUser; it cannot land in v1 because
// adding a method to a published interface breaks every implementor.
func (a *Authenticator) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error {
	// Verify old password
	hash, getErr := a.credentialStore.GetPasswordHash(ctx, userID)
	if getErr != nil {
		return fmt.Errorf("failed to get password hash: %w", getErr)
	}

	if err := bcrypt.CompareHashAndPassword(hash, []byte(oldPassword)); err != nil {
		return ErrInvalidCredentials
	}

	// Validate new password
	if err := a.validatePassword(newPassword); err != nil {
		return err
	}

	// Hash and store new password
	newHash, err := a.hashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	if err := a.credentialStore.StorePasswordHash(ctx, userID, newHash); err != nil {
		return fmt.Errorf("failed to store password: %w", err)
	}

	return nil
}

// ResetPassword resets a user's password (without requiring old password).
// This should be used with additional verification (e.g., email token).
//
// Revocation is the caller's, and it matters more here than in ChangePassword:
// whoever triggers a reset has not proved they hold the old password, so any
// session or refresh token minted before this call may belong to an attacker.
// See ChangePassword for the exact list the caller must revoke (finding F-13,
// CWE-613).
func (a *Authenticator) ResetPassword(ctx context.Context, userID, newPassword string) error {
	// Validate new password
	if err := a.validatePassword(newPassword); err != nil {
		return err
	}

	// Hash and store new password
	hash, err := a.hashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	if err := a.credentialStore.StorePasswordHash(ctx, userID, hash); err != nil {
		return fmt.Errorf("failed to store password: %w", err)
	}

	return nil
}

// validatePassword checks if a password meets minimum requirements.
func (a *Authenticator) validatePassword(password string) error {
	// Both bounds count bytes. The ceiling is bcrypt's own and applies to the
	// UTF-8 encoding, so a multi-byte passphrase reaches it well before its
	// character count suggests (finding F-10, CWE-916).
	if len(password) < MinPasswordLength {
		return ErrWeakPassword
	}
	if len(password) > MaxPasswordLength {
		return ErrPasswordTooLong
	}
	if strings.IndexByte(password, 0) >= 0 {
		return ErrPasswordContainsNUL
	}
	// Add more validation rules as needed (uppercase, numbers, special chars, etc.)
	return nil
}

// hashPassword hashes a password using bcrypt.
func (a *Authenticator) hashPassword(password string) ([]byte, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), a.bcryptCost)
	if err != nil {
		// Unreachable while every caller runs validatePassword first, and kept as
		// the backstop that makes the F-10 guarantee independent of call order.
		if errors.Is(err, bcrypt.ErrPasswordTooLong) {
			return nil, ErrPasswordTooLong
		}
		return nil, err
	}
	return hash, nil
}

// generateID generates a cryptographically secure random ID.
func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hashToken maps a bearer token to the only form the credential store is allowed
// to hold (finding F-05, CWE-522).
//
// SHA-256, not a password KDF: the input is 256 bits from crypto/rand, so there
// is no dictionary to slow an attacker down through, and a work factor would only
// tax the lookup. The digest is base64url-encoded to 43 characters -- the same
// length as the plaintext tokens this replaces, so an existing column fits it.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// GenerateResetToken generates a secure password reset token.
//
// This returns a BEARER value. Handing it to
// storage.CredentialStore.StorePasswordResetToken directly persists a
// replayable secret, which is finding F-05 (CWE-522) reintroduced by the caller:
// the store must only ever see hashToken's output. Use
// Authenticator.GeneratePasswordResetToken, which mints, hashes, stores the hash
// and returns the plaintext for exactly one use -- the email.
func GenerateResetToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// PasswordResetToken represents a stored password reset token.
type PasswordResetToken struct {
	Token     string
	UserID    string
	ExpiresAt time.Time
}

// GeneratePasswordResetToken generates and stores a password reset token for a user.
// The token should be sent to the user's email for verification.
// Returns the generated token which should be included in the password reset link.
//
// The store receives the token's SHA-256 digest, never the token (finding F-05,
// CWE-522). A read of the reset table therefore yields nothing presentable, and
// tokens issued before this change stop validating: their plaintext is on record
// but lookups now hash first. With a one-hour default TTL that window closes on
// its own.
//
// An unknown user still returns ("", nil) -- reporting the miss would be an
// enumeration oracle -- and performs the same mint and hash as a hit, so the two
// paths differ only by one store write rather than by the whole token ceremony
// (finding F-09, CWE-208). The library cannot mask that write without persisting
// junk rows on behalf of unauthenticated strangers, which is a denial-of-service
// primitive in exchange for a smaller timing signal. Rate-limit this endpoint and
// keep the response uniform.
func (a *Authenticator) GeneratePasswordResetToken(ctx context.Context, emailOrUsername string) (string, error) {
	user, lookupErr := a.findUser(ctx, emailOrUsername)
	if lookupErr != nil && !errors.Is(lookupErr, storage.ErrNotFound) {
		return "", lookupErr
	}

	token, err := GenerateResetToken()
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	hashed := hashToken(token)

	if lookupErr != nil {
		return "", nil
	}

	// Store token with expiration
	expiresAt := time.Now().Add(a.passwordResetTTL)
	if err := a.credentialStore.StorePasswordResetToken(ctx, user.ID, hashed, expiresAt); err != nil {
		return "", fmt.Errorf("failed to store token: %w", err)
	}

	return token, nil
}

// ValidatePasswordResetToken validates a password reset token and returns the associated user ID.
//
// It takes the plaintext token from the reset link and hashes it before the
// lookup, so the store compares digest against digest (finding F-05).
func (a *Authenticator) ValidatePasswordResetToken(ctx context.Context, token string) (string, error) {
	userID, err := a.credentialStore.ValidatePasswordResetToken(ctx, hashToken(token))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) || errors.Is(err, storage.ErrExpired) {
			return "", ErrInvalidToken
		}
		return "", fmt.Errorf("failed to validate token: %w", err)
	}

	return userID, nil
}

// CompletePasswordReset validates a password reset token and resets the user's password.
// This is a convenience method that combines token validation and password reset.
//
// If the password is changed but the token cannot be deleted, the returned error
// wraps ErrResetTokenNotRevoked and the password change still happened (finding
// F-12, CWE-613). Distinguish it with errors.Is: retrying the reset is wrong, and
// reporting failure to the user is wrong too, because their password has already
// changed.
//
// Revocation of sessions and refresh tokens is the caller's, and this is the path
// where it matters most -- see ChangePassword for the list (finding F-13).
func (a *Authenticator) CompletePasswordReset(ctx context.Context, token, newPassword string) error {
	// Validate token
	userID, err := a.ValidatePasswordResetToken(ctx, token)
	if err != nil {
		return err
	}

	// Reset password
	if err := a.ResetPassword(ctx, userID, newPassword); err != nil {
		return err
	}

	if err := a.credentialStore.DeletePasswordResetToken(ctx, hashToken(token)); err != nil {
		return fmt.Errorf("%w: %w", ErrResetTokenNotRevoked, err)
	}

	return nil
}

// GenerateEmailVerificationToken generates and stores an email verification token for a user.
// The token should be sent to the user's email for verification.
// Returns the generated token which should be included in the verification link.
//
// As with reset tokens, the store receives only the SHA-256 digest and the
// plaintext is returned once, for the email (finding F-05). Verification tokens
// issued before this change stop validating; the default TTL is 24 hours.
func (a *Authenticator) GenerateEmailVerificationToken(ctx context.Context, userID string) (string, error) {
	// Verify user exists
	user, err := a.userStore.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return "", ErrUserNotFound
		}
		return "", fmt.Errorf("failed to get user: %w", err)
	}

	// Check if already verified
	if user.EmailVerified {
		return "", ErrEmailAlreadyVerified
	}

	// Generate token
	token, err := generateVerificationToken()
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	// Store token with expiration
	expiresAt := time.Now().Add(a.emailVerificationTTL)
	if err := a.credentialStore.StoreEmailVerificationToken(ctx, userID, hashToken(token), expiresAt); err != nil {
		return "", fmt.Errorf("failed to store token: %w", err)
	}

	return token, nil
}

// VerifyEmail verifies a user's email address using a verification token.
//
// If the address is marked verified but the token cannot be deleted, the returned
// error wraps ErrVerificationTokenNotRevoked and the verification still happened
// (the F-12 shape). The alternative -- returning nil and losing the failure -- is
// what the audit found here.
func (a *Authenticator) VerifyEmail(ctx context.Context, token string) error {
	// Validate token
	userID, err := a.credentialStore.ValidateEmailVerificationToken(ctx, hashToken(token))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) || errors.Is(err, storage.ErrExpired) {
			return ErrInvalidToken
		}
		return fmt.Errorf("failed to validate token: %w", err)
	}

	// Get user
	user, err := a.userStore.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	// Mark email as verified
	user.EmailVerified = true
	if err := a.userStore.UpdateUser(ctx, user); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	if err := a.credentialStore.DeleteEmailVerificationToken(ctx, hashToken(token)); err != nil {
		return fmt.Errorf("%w: %w", ErrVerificationTokenNotRevoked, err)
	}

	return nil
}

// ResendEmailVerificationToken generates a new email verification token for a user.
// This is useful when the original token has expired or was lost.
//
// Unlike GeneratePasswordResetToken this reports ErrUserNotFound for an unknown
// address, which is an existence oracle. It is kept for compatibility; a public
// resend endpoint should discard the distinction before answering the client.
func (a *Authenticator) ResendEmailVerificationToken(ctx context.Context, emailOrUsername string) (string, error) {
	user, err := a.findUser(ctx, emailOrUsername)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return "", ErrUserNotFound
		}
		return "", err
	}

	return a.GenerateEmailVerificationToken(ctx, user.ID)
}

// generateVerificationToken generates a secure email verification token.
func generateVerificationToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// TOTP Integration Methods
// These methods provide convenient integration between basic auth and TOTP.

// EnableTOTP enables TOTP for a user and returns the secret and backup codes.
// This is a convenience wrapper around totp.Manager.GenerateSecret.
//
// The factor is stored PENDING and gates nothing until ConfirmTOTP succeeds
// (finding F-07): a user who never scans the QR code, or scans it into a device
// they then lose, is not locked out of their own account. IsTOTPEnabled reports
// false for a pending enrollment and IsTOTPPending reports true.
//
// The returned Secret.BackupCodes are the only plaintext copy that will ever
// exist -- the store receives digests.
func (a *Authenticator) EnableTOTP(ctx context.Context, userID, accountName string) (*totp.Secret, error) {
	if a.totpManager == nil {
		return nil, ErrTOTPNotConfigured
	}

	return a.totpManager.GenerateSecret(ctx, userID, accountName)
}

// ConfirmTOTP arms a pending TOTP enrollment once the user submits a code from
// their authenticator, proving the secret arrived (finding F-07). It is the
// second half of EnableTOTP and a wrapper around totp.Manager.Confirm.
//
// A wrong code leaves the enrollment pending so the user can retry. An
// enrollment that is already armed returns totp.ErrNotPending, and a user with no
// enrollment at all returns totp.ErrNotEnabled.
func (a *Authenticator) ConfirmTOTP(ctx context.Context, userID, code string) error {
	if a.totpManager == nil {
		return ErrTOTPNotConfigured
	}

	return a.totpManager.Confirm(ctx, userID, code)
}

// DisableTOTP disables TOTP for a user.
// Requires a valid TOTP code to prevent accidental or malicious disabling.
//
// A PENDING enrollment is canceled without a code. Demanding proof of possession
// from an authenticator the user may never have reached is precisely the F-07
// lockout, and a factor that has never gated a sign-in protects nothing that
// canceling it could give away.
func (a *Authenticator) DisableTOTP(ctx context.Context, userID, totpCode string) error {
	if a.totpManager == nil {
		return ErrTOTPNotConfigured
	}

	pending, err := a.totpManager.IsPending(ctx, userID)
	if err != nil {
		return err
	}
	if pending {
		return a.totpManager.Disable(ctx, userID)
	}

	// Verify TOTP code before disabling
	valid, err := a.totpManager.Validate(ctx, userID, totpCode)
	if err != nil {
		return err
	}
	if !valid {
		return totp.ErrInvalidCode
	}

	return a.totpManager.Disable(ctx, userID)
}

// AuthenticateWithTOTP authenticates a user with email/username, password, and TOTP code.
// This is a convenience method that combines password and TOTP authentication.
//
// It is the method Authenticate points an ErrMFARequired caller at: both factors
// are verified in one call, and the MFA gate does not fire because the second
// factor is proved here rather than deferred.
//
// The totpCode may be a generated code or a backup code. A generated code that
// already authenticated inside its window returns totp.ErrCodeReused (finding
// F-08); an enrollment awaiting ConfirmTOTP returns totp.ErrPendingConfirmation.
func (a *Authenticator) AuthenticateWithTOTP(ctx context.Context, identifier, password, totpCode string) (*storage.User, error) {
	// First authenticate with password
	user, err := a.authenticatePassword(ctx, identifier, password)
	if err != nil {
		return nil, err
	}

	// Then validate TOTP
	if a.totpManager == nil {
		return nil, ErrTOTPNotConfigured
	}

	valid, err := a.totpManager.Validate(ctx, user.ID, totpCode)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, totp.ErrInvalidCode
	}

	return user, nil
}

// IsTOTPEnabled checks if TOTP is enabled for a user.
//
// An enrollment awaiting ConfirmTOTP reports false (finding F-07), which is what
// keeps Authenticate's MFA gate from locking a user out of a factor they never
// finished setting up. Use IsTOTPPending to tell "never enrolled" from "enrolled,
// not confirmed".
//
// With no TOTP manager configured it answers from the credential store instead of
// reporting false. Reporting false was finding F-35: an application that enrolled
// users through a totp.Manager it built separately, and left Config.TOTPManager
// unset, got "no factor enrolled" for a user who had one -- and because
// RequireMFAWhenEnrolled defaults to EnforceMFA, Authenticate's gate believed it
// and returned the user on the password alone. The store is the authority on
// whether a factor exists; how the caller wired its objects is not.
func (a *Authenticator) IsTOTPEnabled(ctx context.Context, userID string) (bool, error) {
	if a.totpManager == nil {
		state, err := totp.LookupEnrollment(ctx, a.credentialStore, userID)
		if err != nil {
			return false, fmt.Errorf("failed to check second factor: %w", err)
		}
		return state == totp.EnrollmentConfirmed, nil
	}

	return a.totpManager.IsEnabled(ctx, userID)
}

// IsTOTPPending reports whether a user has a TOTP enrollment that is stored but
// not yet confirmed. It reports false when there is no enrollment at all, and,
// like IsTOTPEnabled, answers from the credential store when no TOTP manager is
// configured rather than assuming the absence of one means the absence of a
// factor (F-35).
func (a *Authenticator) IsTOTPPending(ctx context.Context, userID string) (bool, error) {
	if a.totpManager == nil {
		state, err := totp.LookupEnrollment(ctx, a.credentialStore, userID)
		if err != nil {
			return false, fmt.Errorf("failed to check second factor: %w", err)
		}
		return state == totp.EnrollmentPending, nil
	}

	return a.totpManager.IsPending(ctx, userID)
}

// RegenerateTOTPBackupCodes generates new backup codes for a user, replacing the
// old ones. The returned codes are the only plaintext copy; the store receives
// digests.
//
// It refuses an enrollment that is still pending confirmation with
// totp.ErrPendingConfirmation: backup codes for a factor nobody has proved
// possession of would be a standing bypass of ConfirmTOTP.
func (a *Authenticator) RegenerateTOTPBackupCodes(ctx context.Context, userID string) ([]string, error) {
	if a.totpManager == nil {
		return nil, ErrTOTPNotConfigured
	}

	return a.totpManager.RegenerateBackupCodes(ctx, userID)
}
