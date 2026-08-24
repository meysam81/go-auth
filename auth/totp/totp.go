// Package totp provides Time-based One-Time Password (TOTP) authentication
// implementing RFC 6238 for two-factor authentication (2FA).
//
// # Enrollment lifecycle
//
// A factor is enrolled in two steps: GenerateSecret stores the shared secret in
// a PENDING state, and Confirm arms it once the user submits a code proving the
// secret reached their authenticator. Validate refuses a pending secret and
// IsEnabled reports false for one. Callers that cannot yet add the confirmation
// step may set Config.ActivateOnGenerate, which restores the pre-hardening
// behavior and its lockout risk.
//
// # Stored secret payload encoding
//
// storage.CredentialStore has no column for the pending marker and no room for
// a ciphertext discriminator, and its interface cannot change inside v1, so both
// travel inside the secret string itself:
//
//	"$gat1$" <state> "$" <encoding> "$" <data>
//
//	state    "p" pending (awaiting Confirm) | "a" active
//	encoding "r" data is the raw base32 secret
//	         "e" data is standard-base64 of Config.Cipher's ciphertext
//	<data>   the secret in the form named by <encoding>
//
// A stored value that does not begin with "$gat1$" is a legacy row and is read
// as active + raw. The prefix cannot collide with a legacy value: an RFC 4648
// base32 secret is drawn from A-Z, 2-7 and "=", none of which is "$".
//
// An active, unencrypted secret is written in the bare legacy form rather than
// the tagged one, so a deployment that configures no Cipher and sets
// ActivateOnGenerate keeps a byte-identical column and can roll the library
// back. Every other combination is written tagged.
//
// # Backup codes
//
// Backup codes are stored as a keyed SHA-256 digest, never in a recoverable
// form, because they are only ever compared. See hashBackupCode for why a
// password hash is the wrong tool here. Consequently the []string that
// storage.CredentialStore.GetTOTPSecret returns holds digests, not codes: the
// plaintext exists exactly once, in the Secret returned by GenerateSecret and
// in the slice returned by RegenerateBackupCodes, and cannot be recovered
// afterwards.
package totp

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/meysam81/go-auth/storage"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

var (
	// ErrInvalidCode is returned when a TOTP code is invalid.
	ErrInvalidCode = errors.New("invalid TOTP code")

	// ErrAlreadyEnabled is returned when attempting to enable TOTP for a user who already has it enabled.
	// An enrollment still awaiting Confirm also reports as already enabled; Disable clears it so the
	// user can restart enrollment without administrator involvement.
	ErrAlreadyEnabled = errors.New("TOTP already enabled")

	// ErrNotEnabled is returned when attempting TOTP operations for a user who doesn't have it enabled.
	ErrNotEnabled = errors.New("TOTP not enabled")

	// ErrPendingConfirmation is returned when a factor is enrolled but the user has not yet proven
	// possession of the secret by calling Confirm. Codes are refused until then (F-07).
	ErrPendingConfirmation = errors.New("TOTP enrollment awaiting confirmation")

	// ErrNotPending is returned by Confirm when the factor is already armed, so there is nothing
	// to confirm. Re-confirming an active factor is a caller bug, not an authentication.
	ErrNotPending = errors.New("TOTP enrollment is not pending")

	// ErrCodeReused is returned when a code that already authenticated once is presented again
	// inside its validity window (F-08, RFC 6238 section 5.2).
	ErrCodeReused = errors.New("TOTP code already used")

	// ErrCipherRequired is returned when the stored secret is encrypted but no Cipher is configured.
	// Losing the cipher means losing every enrolled factor, so this is surfaced rather than
	// degraded into "not enabled".
	ErrCipherRequired = errors.New("stored TOTP secret is encrypted but no cipher is configured")

	// ErrCorruptSecret is returned when a stored secret carries the library's payload prefix but
	// does not parse. Trust-but-verify: a malformed payload is never treated as a usable secret.
	ErrCorruptSecret = errors.New("stored TOTP secret payload is malformed")

	// ErrReplayGuardFull is returned by MemoryReplayGuard when its entry budget is exhausted.
	// It fails closed: an accepted code that cannot be recorded must not be accepted, because
	// it could then be replayed (F-08).
	ErrReplayGuardFull = errors.New("TOTP replay guard is full")
)

const (
	// DefaultBackupCodeCount is the default number of backup codes to generate.
	DefaultBackupCodeCount = 10

	// DefaultBackupCodeLength is the default length of each backup code.
	DefaultBackupCodeLength = 8

	// TimeStep is the RFC 6238 section 4.1 default time step and the cadence at which the
	// replay guard evicts.
	TimeStep = 30 * time.Second

	// DefaultReplayGuardMaxEntries bounds MemoryReplayGuard's memory. Only codes that already
	// verified against a user's secret are recorded, so the live set is roughly
	// (users authenticating per 90s) x 1, far below this ceiling.
	DefaultReplayGuardMaxEntries = 65536
)

// Payload markers for the stored secret. See the package documentation for the grammar.
const (
	secretPrefix       = "$gat1$"
	secretStatePending = "p"
	secretStateActive  = "a"
	secretEncodingRaw  = "r"
	secretEncodingEnc  = "e"

	// backupCodeHashPrefix tags a stored backup-code digest so a legacy plaintext row remains
	// distinguishable and keeps validating after an upgrade.
	backupCodeHashPrefix = "$gab1$"

	// backupCodeSaltContext domain-separates the per-user salt from any other use of the
	// user ID as key material.
	backupCodeSaltContext = "github.com/meysam81/go-auth/auth/totp/backup-code/v1\x00"

	// replayRetentionSteps is how many time steps an accepted code stays recorded. pquerna's
	// validator accepts a skew of +/-1 step, so a code minted for step c is acceptable while
	// the current step is c-1, c or c+1; measured from the step in which it was first accepted,
	// the last moment it could be accepted again is three steps later.
	replayRetentionSteps = 3
)

// Cipher protects the shared secret at rest (F-06, CWE-522). Implementations must be
// authenticated (AES-GCM, XChaCha20-Poly1305 or equivalent) and safe for concurrent use;
// an unauthenticated cipher lets an attacker with store write access forge a secret.
//
// The library does not implement one: key management, rotation and the KMS boundary are
// the application's, and shipping a default would only encourage a hardcoded key.
type Cipher interface {
	// Encrypt returns the ciphertext of plaintext, including any nonce or authentication tag
	// the implementation needs to decrypt it again.
	Encrypt(plaintext []byte) ([]byte, error)

	// Decrypt reverses Encrypt. It must return an error rather than a best-effort plaintext
	// when authentication fails.
	Decrypt(ciphertext []byte) ([]byte, error)
}

// ReplayGuard remembers codes that have already authenticated, so that a code observed by an
// attacker cannot be presented a second time inside its validity window (F-08, CWE-294,
// RFC 6238 section 5.2).
type ReplayGuard interface {
	// Seen atomically records that code was accepted for userID and reports whether it had
	// already been recorded. It must be safe for concurrent use: the check and the record are
	// one operation, because two simultaneous presentations of the same code would otherwise
	// both observe "not seen".
	//
	// Returning an error causes the code to be rejected. Guards fail closed by design.
	Seen(ctx context.Context, userID, code string) (bool, error)
}

// MemoryReplayGuard is the default ReplayGuard: a process-local set of accepted codes that
// expires entries on the RFC 6238 step boundary.
//
// It protects a single process only. A deployment running more than one instance behind a
// load balancer must supply a shared implementation (Redis SETNX with a TTL is the usual
// shape), or an attacker replays the code against a different instance.
type MemoryReplayGuard struct {
	mu         sync.Mutex
	entries    map[string]time.Time // key -> instant after which the entry is meaningless
	maxEntries int

	// now is injected so the eviction boundary can be tested without sleeping.
	now func() time.Time
}

var _ ReplayGuard = (*MemoryReplayGuard)(nil)

// NewMemoryReplayGuard returns a ReplayGuard that keeps accepted codes in memory for the
// length of the validation window and evicts them afterwards.
func NewMemoryReplayGuard() *MemoryReplayGuard {
	return &MemoryReplayGuard{
		entries:    make(map[string]time.Time),
		maxEntries: DefaultReplayGuardMaxEntries,
		now:        time.Now,
	}
}

// Seen implements ReplayGuard. It purges expired entries on every call, which is what keeps
// the map bounded in a live process; maxEntries is the backstop for a process that is being
// flooded, and exhausting it rejects the code rather than forgetting the ones already held.
func (g *MemoryReplayGuard) Seen(ctx context.Context, userID, code string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("replay guard lookup: %w", err)
	}

	// A NUL separator keeps ("ab", "c") and ("a", "bc") distinct; neither a user ID nor a
	// decimal code can contain one.
	key := userID + "\x00" + code
	now := g.now()

	g.mu.Lock()
	defer g.mu.Unlock()

	for k, expiry := range g.entries {
		if !expiry.After(now) {
			delete(g.entries, k)
		}
	}

	if expiry, ok := g.entries[key]; ok && expiry.After(now) {
		return true, nil
	}

	if len(g.entries) >= g.maxEntries {
		return false, ErrReplayGuardFull
	}

	g.entries[key] = now.Truncate(TimeStep).Add(replayRetentionSteps * TimeStep)
	return false, nil
}

// Manager handles TOTP operations.
type Manager struct {
	credentialStore    storage.CredentialStore
	issuer             string
	backupCodeCount    int
	cipher             Cipher
	replayGuard        ReplayGuard
	activateOnGenerate bool
}

// Config configures the TOTP manager.
type Config struct {
	CredentialStore storage.CredentialStore
	Issuer          string // The name of your application (e.g., "MyApp")
	BackupCodeCount int    // Optional: defaults to DefaultBackupCodeCount

	// Cipher optionally encrypts the shared secret before it reaches CredentialStore and
	// decrypts it on read (F-06). Leaving it nil preserves the historical behavior: the
	// secret is persisted verbatim, and a single read of the store yields a working second
	// factor for every enrolled user.
	//
	// Configuring a Cipher on a deployment with existing enrollments is safe. A legacy row is
	// still readable, and it is re-encrypted the next time the row is rewritten (Confirm or
	// RegenerateBackupCodes). Removing a Cipher afterwards is not: ErrCipherRequired.
	Cipher Cipher

	// ReplayGuard rejects a code that has already authenticated inside its validity window
	// (F-08). Leaving it nil installs NewMemoryReplayGuard, which is correct for a
	// single-process deployment and insufficient for a multi-instance one.
	ReplayGuard ReplayGuard

	// ActivateOnGenerate arms the factor the moment GenerateSecret stores it, instead of
	// waiting for Confirm. It exists so a caller upgrading within v1 is not broken silently
	// by the F-07 fix; the safe default is false.
	//
	// Setting it re-opens F-07: a user who never scans the QR code, or scans it into a device
	// they then lose, is locked out with no self-service path.
	//
	// Deprecated: this is a migration shim for the F-07 fix and v2 removes it. Add a
	// confirmation step that calls Confirm and leave this false.
	ActivateOnGenerate bool
}

// NewManager creates a new TOTP manager.
//
// Supplying Config.Cipher is strongly recommended. Without it the shared secret is written to
// CredentialStore in plaintext, so a leaked backup, a snapshot on shared storage or a SQL
// injection elsewhere in the host application hands the attacker a working second factor for
// every enrolled user — exactly the property the factor exists to deny (F-06, CWE-522).
// Backup codes are hashed either way and are never recoverable from the store.
func NewManager(cfg Config) (*Manager, error) {
	if cfg.CredentialStore == nil {
		return nil, errors.New("credential store is required")
	}
	if cfg.Issuer == "" {
		return nil, errors.New("issuer is required")
	}

	backupCodeCount := cfg.BackupCodeCount
	if backupCodeCount == 0 {
		backupCodeCount = DefaultBackupCodeCount
	}

	replayGuard := cfg.ReplayGuard
	if replayGuard == nil {
		replayGuard = NewMemoryReplayGuard()
	}

	return &Manager{
		credentialStore:    cfg.CredentialStore,
		issuer:             cfg.Issuer,
		backupCodeCount:    backupCodeCount,
		cipher:             cfg.Cipher,
		replayGuard:        replayGuard,
		activateOnGenerate: cfg.ActivateOnGenerate,
	}, nil
}

// Secret represents a TOTP secret with associated metadata.
type Secret struct {
	Secret      string   // Base32-encoded secret
	URL         string   // otpauth:// URL for QR code generation
	QRCode      string   // otpauth:// URL for QR code generation (client should generate QR code from this URL)
	BackupCodes []string // One-time use backup codes

	// Pending reports that the factor is stored but not yet armed, and that Confirm must be
	// called with a code from the user's authenticator before it will validate anything.
	// It is false only when Config.ActivateOnGenerate is set.
	Pending bool
}

// GenerateSecret generates a new TOTP secret for a user.
// Returns the secret, backup codes, and a QR code URL.
//
// The factor is stored PENDING: it does not validate and IsEnabled reports false until
// Confirm succeeds (F-07). The returned BackupCodes are the only copy that will ever exist in
// plaintext — the store receives digests.
//
// An enrollment that is already present, pending or armed, returns ErrAlreadyEnabled. Disable
// clears a pending enrollment so the user can restart.
func (m *Manager) GenerateSecret(ctx context.Context, userID, accountName string) (*Secret, error) {
	// Check if TOTP is already enabled
	_, _, err := m.credentialStore.GetTOTPSecret(ctx, userID)
	if err == nil {
		return nil, ErrAlreadyEnabled
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("failed to check existing secret: %w", err)
	}

	// Generate TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      m.issuer,
		AccountName: accountName,
		SecretSize:  32, // 256 bits
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP key: %w", err)
	}

	// Generate backup codes
	backupCodes, err := m.generateBackupCodes()
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	hashedCodes, err := hashBackupCodes(userID, backupCodes)
	if err != nil {
		return nil, fmt.Errorf("failed to hash backup codes: %w", err)
	}

	pending := !m.activateOnGenerate
	payload, err := encodeSecret(key.Secret(), pending, m.cipher)
	if err != nil {
		return nil, fmt.Errorf("failed to encode TOTP secret: %w", err)
	}

	// Store the secret and backup codes
	if err := m.credentialStore.StoreTOTPSecret(ctx, userID, payload, hashedCodes); err != nil {
		return nil, fmt.Errorf("failed to store TOTP secret: %w", err)
	}

	return &Secret{
		Secret:      key.Secret(),
		URL:         key.URL(),
		QRCode:      key.URL(), // Client should generate QR code from this URL
		BackupCodes: backupCodes,
		Pending:     pending,
	}, nil
}

// Confirm arms a pending enrollment once the user proves possession of the secret (F-07).
//
// It returns ErrInvalidCode when the code does not match, leaving the enrollment pending so the
// user may retry; ErrNotPending when the factor is already armed; and ErrNotEnabled when there
// is no enrollment at all. The confirming code is recorded with the ReplayGuard, so it cannot
// immediately be replayed as a sign-in.
func (m *Manager) Confirm(ctx context.Context, userID, code string) error {
	stored, hashedCodes, err := m.credentialStore.GetTOTPSecret(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrNotEnabled
		}
		return fmt.Errorf("failed to get TOTP secret: %w", err)
	}

	secret, pending, err := m.decodeSecret(stored)
	if err != nil {
		return err
	}
	if !pending {
		return ErrNotPending
	}

	if !totp.Validate(code, secret) {
		return ErrInvalidCode
	}
	if recordErr := m.recordCode(ctx, userID, code); recordErr != nil {
		return recordErr
	}

	// Rewriting the row is also the migration point for a Cipher configured after enrollment:
	// encodeSecret re-encodes with whatever is configured now. The digests are re-stored
	// verbatim because GetTOTPSecret already returns only the unused ones.
	payload, err := encodeSecret(secret, false, m.cipher)
	if err != nil {
		return fmt.Errorf("failed to encode TOTP secret: %w", err)
	}
	if err := m.credentialStore.StoreTOTPSecret(ctx, userID, payload, hashedCodes); err != nil {
		return fmt.Errorf("failed to arm TOTP secret: %w", err)
	}

	return nil
}

// Validate verifies a TOTP code for a user.
// Returns true if the code is valid (either TOTP or backup code).
//
// A pending enrollment returns ErrPendingConfirmation (F-07). A generated code that already
// authenticated inside its window returns ErrCodeReused (F-08); backup codes are exempt from
// the replay guard because they are single-use by their own mechanism.
func (m *Manager) Validate(ctx context.Context, userID, code string) (bool, error) {
	stored, hashedCodes, err := m.credentialStore.GetTOTPSecret(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return false, ErrNotEnabled
		}
		return false, fmt.Errorf("failed to get TOTP secret: %w", err)
	}

	secret, pending, err := m.decodeSecret(stored)
	if err != nil {
		return false, err
	}
	if pending {
		return false, ErrPendingConfirmation
	}

	// Try TOTP validation first. The replay guard is consulted only once the code has already
	// verified against the secret, so a guessing attacker cannot use it to grow the guard's
	// state: recording an unverified code would make the guard the memory-exhaustion vector
	// it is supposed to prevent.
	if totp.Validate(code, secret) {
		if recordErr := m.recordCode(ctx, userID, code); recordErr != nil {
			return false, recordErr
		}
		return true, nil
	}

	return m.useBackupCode(ctx, userID, code, hashedCodes)
}

// ValidateBackupCode validates a backup code for a user.
// This is useful when you want to explicitly validate a backup code.
//
// Comparison is constant-time against the stored digests (F-06). A pending enrollment returns
// ErrPendingConfirmation: backup codes must not rescue a factor whose secret was never
// confirmed.
func (m *Manager) ValidateBackupCode(ctx context.Context, userID, code string) (bool, error) {
	stored, hashedCodes, err := m.credentialStore.GetTOTPSecret(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return false, ErrNotEnabled
		}
		return false, fmt.Errorf("failed to get TOTP secret: %w", err)
	}

	pending, err := storedSecretIsPending(stored)
	if err != nil {
		return false, err
	}
	if pending {
		return false, ErrPendingConfirmation
	}

	return m.useBackupCode(ctx, userID, code, hashedCodes)
}

// useBackupCode consumes the stored entry matching code, if any.
func (m *Manager) useBackupCode(ctx context.Context, userID, code string, storedCodes []string) (bool, error) {
	match, ok, err := matchBackupCode(userID, code, storedCodes)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}

	// UseBackupCode is keyed by the value the store holds, which is the digest.
	if err := m.credentialStore.UseBackupCode(ctx, userID, match); err != nil {
		return false, fmt.Errorf("failed to use backup code: %w", err)
	}
	return true, nil
}

// recordCode asks the replay guard whether code has already authenticated for userID, and
// records it otherwise. Both a guard failure and a replay deny the code.
func (m *Manager) recordCode(ctx context.Context, userID, code string) error {
	if m.replayGuard == nil {
		return nil
	}
	seen, err := m.replayGuard.Seen(ctx, userID, code)
	if err != nil {
		return fmt.Errorf("replay guard: %w", err)
	}
	if seen {
		return ErrCodeReused
	}
	return nil
}

// Disable disables TOTP for a user.
// It also cancels an enrollment that is still pending confirmation, which is the documented
// way for a user to restart enrollment after losing the device mid-flow.
func (m *Manager) Disable(ctx context.Context, userID string) error {
	// Check if TOTP is enabled
	_, _, err := m.credentialStore.GetTOTPSecret(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrNotEnabled
		}
		return fmt.Errorf("failed to get TOTP secret: %w", err)
	}

	if err := m.credentialStore.DeleteTOTPSecret(ctx, userID); err != nil {
		return fmt.Errorf("failed to delete TOTP secret: %w", err)
	}

	return nil
}

// IsEnabled checks if TOTP is enabled for a user.
//
// An enrollment awaiting Confirm reports false (F-07): a factor that has never validated a code
// must not gate a sign-in, or the user is locked out by their own half-finished enrollment.
// Use IsPending to tell "never enrolled" from "enrolled, not confirmed".
func (m *Manager) IsEnabled(ctx context.Context, userID string) (bool, error) {
	stored, _, err := m.credentialStore.GetTOTPSecret(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check TOTP status: %w", err)
	}

	// Reading the state does not need the cipher, so a misconfigured Cipher cannot make a
	// user's factor silently disappear from this check.
	pending, err := storedSecretIsPending(stored)
	if err != nil {
		return false, err
	}
	return !pending, nil
}

// IsPending reports whether a user has an enrollment that is stored but not yet confirmed.
// It returns false when there is no enrollment at all.
func (m *Manager) IsPending(ctx context.Context, userID string) (bool, error) {
	stored, _, err := m.credentialStore.GetTOTPSecret(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check TOTP status: %w", err)
	}
	return storedSecretIsPending(stored)
}

// RegenerateBackupCodes generates new backup codes for a user, replacing the old ones.
// The returned codes are the only plaintext copy; the store receives digests.
//
// It refuses a pending enrollment: codes for a factor that was never confirmed would be a
// standing bypass of the confirmation step.
func (m *Manager) RegenerateBackupCodes(ctx context.Context, userID string) ([]string, error) {
	// Get existing secret
	stored, _, err := m.credentialStore.GetTOTPSecret(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrNotEnabled
		}
		return nil, fmt.Errorf("failed to get TOTP secret: %w", err)
	}

	secret, pending, err := m.decodeSecret(stored)
	if err != nil {
		return nil, err
	}
	if pending {
		return nil, ErrPendingConfirmation
	}

	// Generate new backup codes
	backupCodes, err := m.generateBackupCodes()
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	hashedCodes, err := hashBackupCodes(userID, backupCodes)
	if err != nil {
		return nil, fmt.Errorf("failed to hash backup codes: %w", err)
	}

	// Re-encoding here also migrates a legacy plaintext row to ciphertext once a Cipher is
	// configured.
	payload, err := encodeSecret(secret, false, m.cipher)
	if err != nil {
		return nil, fmt.Errorf("failed to encode TOTP secret: %w", err)
	}

	// Store with new backup codes
	if err := m.credentialStore.StoreTOTPSecret(ctx, userID, payload, hashedCodes); err != nil {
		return nil, fmt.Errorf("failed to store backup codes: %w", err)
	}

	return backupCodes, nil
}

// GenerateQRCodeURL generates an otpauth:// URL for QR code generation.
// This is a convenience method for getting the URL without generating a new secret.
//
// It deliberately works for a pending enrollment, because rendering the QR code is what the
// user does before they can call Confirm. The URL carries the shared secret: treat the
// returned string as the secret it contains, and never log it.
func (m *Manager) GenerateQRCodeURL(ctx context.Context, userID, accountName string) (string, error) {
	stored, _, err := m.credentialStore.GetTOTPSecret(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return "", ErrNotEnabled
		}
		return "", fmt.Errorf("failed to get TOTP secret: %w", err)
	}

	secret, _, err := m.decodeSecret(stored)
	if err != nil {
		return "", err
	}

	key, err := otp.NewKeyFromURL(fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
		m.issuer, accountName, secret, m.issuer))
	if err != nil {
		return "", fmt.Errorf("failed to create key: %w", err)
	}

	return key.URL(), nil
}

// generateBackupCodes generates cryptographically secure backup codes.
func (m *Manager) generateBackupCodes() ([]string, error) {
	codes := make([]string, m.backupCodeCount)
	for i := 0; i < m.backupCodeCount; i++ {
		code, err := generateBackupCode()
		if err != nil {
			return nil, err
		}
		codes[i] = code
	}
	return codes, nil
}

// generateBackupCode generates a single backup code.
// Format: XXXX-XXXX (8 characters, uppercase alphanumeric, dash-separated)
func generateBackupCode() (string, error) {
	// Generate 5 random bytes
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode to base32 without padding and take first 8 characters
	code := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	if len(code) < 8 {
		// This should never happen, but handle it just in case
		return generateBackupCode()
	}
	code = code[:8]

	// Format: XXXX-XXXX
	return code[:4] + "-" + code[4:8], nil
}

// GenerateCurrentCode generates the current TOTP code for a user.
//
// DEBUG AND TEST USE ONLY. It derives a live second-factor code from the stored secret, so any
// route that reaches it is a complete bypass of the second factor for whoever can call it.
// Never expose it through an HTTP handler, an admin console or a support tool.
func (m *Manager) GenerateCurrentCode(ctx context.Context, userID string) (string, error) {
	stored, _, err := m.credentialStore.GetTOTPSecret(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return "", ErrNotEnabled
		}
		return "", fmt.Errorf("failed to get TOTP secret: %w", err)
	}

	secret, _, err := m.decodeSecret(stored)
	if err != nil {
		return "", err
	}

	code, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{})
	if err != nil {
		return "", fmt.Errorf("failed to generate code: %w", err)
	}

	return code, nil
}

// encodeSecret renders secret into the stored payload described in the package documentation.
//
// An active, unencrypted secret is written bare so the column stays byte-identical to what
// pre-hardening versions wrote; every other combination needs the tag to be readable at all.
func encodeSecret(secret string, pending bool, cipher Cipher) (string, error) {
	if !pending && cipher == nil {
		return secret, nil
	}

	state := secretStateActive
	if pending {
		state = secretStatePending
	}

	if cipher == nil {
		return secretPrefix + state + "$" + secretEncodingRaw + "$" + secret, nil
	}

	ciphertext, err := cipher.Encrypt([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("encrypt TOTP secret: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(ciphertext)
	return secretPrefix + state + "$" + secretEncodingEnc + "$" + encoded, nil
}

// splitSecretPayload parses a stored payload into its state, encoding and data. A value with no
// payload prefix is a legacy row: active, raw.
func splitSecretPayload(stored string) (state, encoding, data string, err error) {
	if !strings.HasPrefix(stored, secretPrefix) {
		return secretStateActive, secretEncodingRaw, stored, nil
	}

	// "$gat1$a$r$DATA" splits into ["", "gat1", "a", "r", "DATA"]. The data field is base32 or
	// base64 and never contains "$", but SplitN keeps any stray one attached to the data rather
	// than silently truncating the secret.
	parts := strings.SplitN(stored, "$", 5)
	if len(parts) != 5 {
		return "", "", "", ErrCorruptSecret
	}

	state, encoding, data = parts[2], parts[3], parts[4]
	if state != secretStateActive && state != secretStatePending {
		return "", "", "", ErrCorruptSecret
	}
	if encoding != secretEncodingRaw && encoding != secretEncodingEnc {
		return "", "", "", ErrCorruptSecret
	}
	if data == "" {
		return "", "", "", ErrCorruptSecret
	}
	return state, encoding, data, nil
}

// storedSecretIsPending reports the enrollment state without needing the Cipher, so a state
// check never depends on key material being available.
func storedSecretIsPending(stored string) (bool, error) {
	state, _, _, err := splitSecretPayload(stored)
	if err != nil {
		return false, err
	}
	return state == secretStatePending, nil
}

// decodeSecret recovers the base32 shared secret and the enrollment state from a stored payload.
func (m *Manager) decodeSecret(stored string) (secret string, pending bool, err error) {
	state, encoding, data, err := splitSecretPayload(stored)
	if err != nil {
		return "", false, err
	}
	pending = state == secretStatePending

	if encoding == secretEncodingRaw {
		return data, pending, nil
	}

	if m.cipher == nil {
		return "", false, ErrCipherRequired
	}
	ciphertext, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", false, fmt.Errorf("%w: %w", ErrCorruptSecret, err)
	}
	plaintext, err := m.cipher.Decrypt(ciphertext)
	if err != nil {
		return "", false, fmt.Errorf("decrypt TOTP secret: %w", err)
	}
	return string(plaintext), pending, nil
}

// normalizeBackupCode folds the presentation of a backup code (dashes, case, surrounding
// whitespace) so that what the user types matches what was generated.
func normalizeBackupCode(code string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
}

// hashBackupCode derives the stored representation of a backup code (F-06).
//
// Why a keyed SHA-256 and not bcrypt/argon2: Validate compares the presented code against every
// unused code, so a password hash costs (codes x work factor) per attempt — ten cost-12 bcrypt
// evaluations is roughly 2.5 seconds of CPU on every second-factor submission, which is a
// denial-of-service primitive pointed at the sign-in path. A backup code is not a password: it
// is machine-generated with 40 bits of entropy from crypto/rand and has no dictionary
// structure, so the slow-hash property that protects a human-chosen password buys much less
// here.
//
// The salt is derived from the user ID rather than stored, because the CredentialStore
// interface has no column for one in v1. It is not secret; its job is to stop one precomputed
// table from covering every user, and to stop the identical digest of a shared code from
// appearing under two accounts.
//
// The residual risk is honest: 40 bits is brute-forceable offline by an attacker holding the
// store, per user, at GPU speed. The mitigations are the per-user salt (no amortization across
// accounts), single use, and the fact that the codes are the fallback path rather than the
// primary factor. Widening the code and storing a real random salt is v2 work, because both
// change the stored shape.
func hashBackupCode(userID, code string) (string, error) {
	mac := hmac.New(sha256.New, backupCodeSalt(userID))
	if _, err := mac.Write([]byte(normalizeBackupCode(code))); err != nil {
		return "", fmt.Errorf("hash backup code: %w", err)
	}
	return backupCodeHashPrefix + hex.EncodeToString(mac.Sum(nil)), nil
}

// backupCodeSalt derives the per-user HMAC key, domain-separated from any other use of the
// user ID as key material.
func backupCodeSalt(userID string) []byte {
	sum := sha256.Sum256([]byte(backupCodeSaltContext + userID))
	return sum[:]
}

// hashBackupCodes maps generated codes to their stored representation.
func hashBackupCodes(userID string, codes []string) ([]string, error) {
	hashed := make([]string, len(codes))
	for i, code := range codes {
		h, err := hashBackupCode(userID, code)
		if err != nil {
			return nil, err
		}
		hashed[i] = h
	}
	return hashed, nil
}

// matchBackupCode finds the stored entry corresponding to the presented code and returns it
// verbatim, so the caller can hand it back to CredentialStore.UseBackupCode.
//
// The scan does not stop at the first match and never branches on a comparison result: with an
// early exit, the time to a rejection would reveal how many entries were examined, and with a
// match, which slot matched. A row written before this release is still plaintext, so both
// shapes are compared, each in constant time (F-06).
func matchBackupCode(userID, code string, storedCodes []string) (string, bool, error) {
	presentedPlain := normalizeBackupCode(code)
	if presentedPlain == "" {
		// An empty submission would compare equal to an empty stored entry, so it is refused
		// before the scan rather than being allowed to depend on the store's contents.
		return "", false, nil
	}

	presentedHash, err := hashBackupCode(userID, code)
	if err != nil {
		return "", false, err
	}

	matchIndex := -1
	for i, stored := range storedCodes {
		var equal int
		if strings.HasPrefix(stored, backupCodeHashPrefix) {
			equal = subtle.ConstantTimeCompare([]byte(presentedHash), []byte(stored))
		} else {
			equal = subtle.ConstantTimeCompare([]byte(presentedPlain), []byte(normalizeBackupCode(stored)))
		}
		matchIndex = subtle.ConstantTimeSelect(equal, i, matchIndex)
	}

	if matchIndex < 0 {
		return "", false, nil
	}
	return storedCodes[matchIndex], true, nil
}
