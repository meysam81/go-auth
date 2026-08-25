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
// The tag has to sit outside the ciphertext, because IsEnabled must answer
// without key material. That leaves it writable by anyone who can write to the
// store, so encoding "e" seals a copy of the tag, plus a digest of the user ID,
// INSIDE the authenticated plaintext, and they are checked after decrypt:
//
//	"$gat1$" <state> "$e$" <sha256 of the user ID> "$" <secret>
//
// Rewriting "$gat1$a$e$..." to "$gat1$a$r$<attacker secret>", flipping "p" to
// "a", or copying a sealed row from one account onto another therefore fails
// authentication instead of being honored (ErrSecretTampered). The last of
// those is why the user ID is in there: a store writer who enrolls a factor of
// their own and copies that perfectly genuine row over someone else's passes
// every check the markers alone can make. For the same reason a configured
// Cipher refuses to read an unencrypted secret at all; see
// Config.AllowLegacyPlaintextSecrets for the one-way migration window.
//
// # Backup codes
//
// Backup codes are stored as a keyed SHA-256 digest, sealed with Config.Cipher
// when one is configured, and never in a recoverable form: they are only ever
// compared. See hashBackupCode for why a password hash is the wrong tool here.
// Consequently the []string that storage.CredentialStore.GetTOTPSecret returns
// holds digests, not codes: the plaintext exists exactly once, in the Secret
// returned by GenerateSecret and in the slice returned by
// RegenerateBackupCodes, and cannot be recovered afterwards.
//
//	"$gab1$" <hex>     keyed SHA-256 digest of the normalized code
//	"$gab2$" <base64>  standard-base64 of Config.Cipher sealing a "$gab1$" digest
//
// A stored value with neither prefix is a legacy plaintext code and still
// validates, so an upgrade does not invalidate a printed sheet.
//
// # Availability of the Cipher
//
// Once a Cipher is configured it guards both factors: an unreadable key makes
// the shared secret and every code sealed under it unusable, which is a lockout
// rather than a bypass. Give it the availability of the store itself, and roll
// keys by re-encrypting rows (Confirm and RegenerateBackupCodes rewrite them)
// rather than by removing the old key.
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
	"net/url"
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

	// ErrSecretNotEncrypted is returned when a Cipher is configured but the stored secret is
	// not encrypted. Reading it anyway would let anyone who can write to the store replace a
	// sealed secret with one of their own, which is the adversary the Cipher exists for.
	// Config.AllowLegacyPlaintextSecrets opens a migration window for rows written before the
	// Cipher was configured.
	ErrSecretNotEncrypted = errors.New("stored TOTP secret is not encrypted but a cipher is configured")

	// ErrSecretTampered is returned when what a stored payload claims in the clear -- its
	// state and encoding markers, and the account it sits under -- disagrees with what was
	// sealed inside its ciphertext. The markers must stay outside so the enrollment state is
	// readable without key material, so they are bound inside as well; a mismatch means the
	// payload was rewritten, or moved between accounts, after the library sealed it.
	ErrSecretTampered = errors.New("stored TOTP secret payload does not match its sealed tag")
)

const (
	// DefaultBackupCodeCount is the default number of backup codes to generate.
	DefaultBackupCodeCount = 10

	// DefaultBackupCodeLength is the number of base32 characters in each backup code, excluding
	// the dashes that group them. Ten random bytes give 80 bits, which is the entropy the
	// stored digest ultimately rests on: see hashBackupCode for why the digest is a single
	// unkeyed-strength pass and therefore why the code itself has to be wide.
	DefaultBackupCodeLength = 16

	// backupCodeBytes is the entropy behind one backup code. base32 emits 8 characters per 5
	// bytes, so this is DefaultBackupCodeLength * 5 / 8 and the two must move together.
	backupCodeBytes = DefaultBackupCodeLength * 5 / 8

	// backupCodeGroup is how many characters separate one dash from the next. Grouping is for
	// the human retyping the code off a printout; it is stripped before hashing.
	backupCodeGroup = 4

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

	// backupCodeSealPrefix tags a digest that Config.Cipher has sealed. The digest's own prefix
	// travels inside the ciphertext, so a value that opens to something else was not written
	// by this library.
	backupCodeSealPrefix = "$gab2$"

	// accountBindingContext domain-separates the account marker sealed into an encrypted
	// secret from any other use of the user ID as an input to SHA-256 here.
	accountBindingContext = "github.com/meysam81/go-auth/auth/totp/account-binding/v1\x00"

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
	// code arrives folded to the form the validator compared (see normalizeSubmittedCode), so
	// every presentation of one accepted code reaches an implementation as one string.
	// Implementations must key on it verbatim: folding it further merges codes the validator
	// keeps apart, and no implementation can un-fold what it was handed.
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
	order      []replayRecord       // the same keys in expiry order, so eviction is not a full sweep
	maxEntries int

	// now is injected so the eviction boundary can be tested without sleeping.
	now func() time.Time
}

// replayRecord is one queued eviction: the key to drop and the instant it stops mattering.
type replayRecord struct {
	key    string
	expiry time.Time
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

// Seen implements ReplayGuard. It evicts the entries whose window has closed on every call,
// which is what keeps the map bounded in a live process; maxEntries is the backstop for a
// process that is being flooded, and exhausting it rejects the code rather than forgetting the
// ones already held.
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

	g.evictExpired(now)

	if expiry, ok := g.entries[key]; ok && expiry.After(now) {
		return true, nil
	}

	if len(g.entries) >= g.maxEntries {
		return false, ErrReplayGuardFull
	}

	expiry := now.Truncate(TimeStep).Add(replayRetentionSteps * TimeStep)
	g.entries[key] = expiry
	g.order = append(g.order, replayRecord{key: key, expiry: expiry})
	return false, nil
}

// evictExpired drops the records whose acceptance window has closed. The caller holds g.mu.
//
// An expiry is truncate(insertion) + replayRetentionSteps, which is monotonic in the insertion
// instant, so g.order is in expiry order and the scan stops at the first live record: each
// record is appended once and dropped once, making eviction amortized O(1) per call. It
// replaces a sweep of the whole map, which under a flood turned every single validation into a
// walk of every entry held, with the one global mutex taken for the length of that walk.
//
// A clock that steps backwards can leave an expired record queued behind a live one. That
// delays its eviction until the record in front of it expires; it never resurrects the entry,
// because acceptance is decided by the map's own expiry.
func (g *MemoryReplayGuard) evictExpired(now time.Time) {
	live := 0
	for ; live < len(g.order); live++ {
		record := g.order[live]
		if record.expiry.After(now) {
			break
		}
		// The map may hold a NEWER expiry for this key, recorded after this record expired.
		// Deleting on the key alone would then forget a code that is still spent.
		if expiry, ok := g.entries[record.key]; ok && !expiry.After(now) {
			delete(g.entries, record.key)
		}
	}

	// Resliced rather than copied down: the dropped prefix is reclaimed the next time append
	// has to grow the backing array, and that growth copies only the records still queued.
	g.order = g.order[live:]
}

// Manager handles TOTP operations.
type Manager struct {
	credentialStore      storage.CredentialStore
	issuer               string
	backupCodeCount      int
	cipher               Cipher
	replayGuard          ReplayGuard
	activateOnGenerate   bool
	allowLegacyPlaintext bool
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
	// Configuring a Cipher on a deployment with existing enrollments needs one migration
	// window: a row written before the Cipher existed is plaintext, and a configured Cipher
	// refuses to read plaintext unless AllowLegacyPlaintextSecrets says so. Rows are
	// re-encrypted as they are rewritten (Confirm or RegenerateBackupCodes). Removing a
	// Cipher afterwards is not supported at all: ErrCipherRequired.
	Cipher Cipher

	// AllowLegacyPlaintextSecrets lets a configured Cipher read a secret stored in the bare
	// pre-hardening form, so that adopting a Cipher does not lock out every existing
	// enrollment at once. Rows migrate to ciphertext as they are rewritten, and the flag can
	// be cleared once none is left.
	//
	// It weakens the guarantee while it is set: an attacker who can write to the store can
	// strip the payload tag off a sealed row and leave a secret of their own in the legacy
	// shape, which is the downgrade the sealed tag exists to detect (ErrSecretTampered). A
	// TAGGED but unencrypted row ("$gat1$a$r$...") is refused whatever this flag says, because
	// the library never writes one while a Cipher is configured, so no migration can produce
	// it and nothing but a rewrite explains it.
	//
	// Deprecated: this is a migration shim for the F-06 fix and v2 removes it. Re-encrypt the
	// remaining rows and leave this false.
	AllowLegacyPlaintextSecrets bool

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
		credentialStore:      cfg.CredentialStore,
		issuer:               cfg.Issuer,
		backupCodeCount:      backupCodeCount,
		cipher:               cfg.Cipher,
		replayGuard:          replayGuard,
		activateOnGenerate:   cfg.ActivateOnGenerate,
		allowLegacyPlaintext: cfg.AllowLegacyPlaintextSecrets,
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

	hashedCodes, err := storedBackupCodes(userID, backupCodes, m.cipher)
	if err != nil {
		return nil, fmt.Errorf("failed to hash backup codes: %w", err)
	}

	pending := !m.activateOnGenerate
	payload, err := encodeSecret(userID, key.Secret(), pending, m.cipher)
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

	secret, pending, err := m.decodeSecret(userID, stored)
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
	payload, err := encodeSecret(userID, secret, false, m.cipher)
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

	secret, pending, err := m.decodeSecret(userID, stored)
	if err != nil {
		return false, err
	}
	if pending {
		return false, ErrPendingConfirmation
	}

	// Try TOTP validation first. The replay guard is consulted only once the code has already
	// verified against the secret, so a guessing attacker cannot use it to grow the guard's
	// state: recording an unverified code would make the guard the memory-exhaustion vector
	// it is supposed to prevent. recordCode keys on the same folded form the validator
	// compared, so no presentation of an accepted code escapes the guard.
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

	pending, err := m.storedSecretIsPending(stored)
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
	match, ok, err := matchBackupCode(m.cipher, userID, code, storedCodes)
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

// normalizeSubmittedCode folds a submitted code exactly the way the validator folds it.
//
// hotp.ValidateCustom trims the passcode with strings.TrimSpace before comparing, so "170225"
// and " 170225" are one code to the validator. Keying the replay guard on the raw submission
// therefore gave a single accepted code an unbounded set of guard keys -- strings.TrimSpace
// cuts every Unicode space, in any combination, at either end -- and each of them replayed
// successfully while the guard believed it had never seen the code (F-08).
//
// This must stay identical to the rule the validator applies. A normalization of our own
// invention, however much stricter it looked, would reopen the same gap the moment the two
// disagreed about one character.
func normalizeSubmittedCode(code string) string {
	return strings.TrimSpace(code)
}

// recordCode asks the replay guard whether code has already authenticated for userID, and
// records it otherwise. Both a guard failure and a replay deny the code.
//
// It is the only place a guard key is built, so the normalization above cannot be skipped by
// one caller: Validate and Confirm both arrive here.
func (m *Manager) recordCode(ctx context.Context, userID, code string) error {
	if m.replayGuard == nil {
		return nil
	}
	seen, err := m.replayGuard.Seen(ctx, userID, normalizeSubmittedCode(code))
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

// Enrollment describes what a credential store holds for one user's TOTP factor.
type Enrollment int

const (
	// EnrollmentNone means the store holds no TOTP secret for the user.
	EnrollmentNone Enrollment = iota

	// EnrollmentPending means a secret is stored but no code has ever validated against it, so
	// the user has not proved possession and the factor must not gate a sign-in (F-07).
	EnrollmentPending

	// EnrollmentConfirmed means the user has proved possession and the factor is armed.
	EnrollmentConfirmed
)

// LookupEnrollment reports whether a user holds a TOTP factor, reading the credential store
// directly. It needs no Manager, no issuer, and no Cipher.
//
// It exists because "is a second factor enrolled?" is a question about the store, not about how
// the caller happened to wire its objects, and answering it from a possibly-absent Manager is how
// finding F-35 turned a half-wired application into a silent MFA bypass: a component that had not
// been handed a Manager reported "no factor enrolled" for a user who had one, and the sign-in gate
// believed it. A question whose wrong answer is a bypass may not depend on optional wiring.
//
// Deliberately NOT applied here: the stored-encoding policy Manager enforces (refusing a plaintext
// payload once a Cipher is configured, F-33). This function classifies state only, so a downgraded
// row is reported as EnrollmentConfirmed rather than rejected. That direction is the safe one for a
// gate -- it demands the second factor -- but it means this is an enrollment *check*, never an
// authentication decision. Validating a code stays on Manager, which does apply the policy.
func LookupEnrollment(ctx context.Context, store storage.CredentialStore, userID string) (Enrollment, error) {
	if store == nil {
		return EnrollmentNone, errors.New("totp: credential store is required")
	}

	stored, _, err := store.GetTOTPSecret(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return EnrollmentNone, nil
		}
		return EnrollmentNone, fmt.Errorf("failed to check TOTP status: %w", err)
	}

	state, _, _, err := splitSecretPayload(stored)
	if err != nil {
		return EnrollmentNone, err
	}
	if state == secretStatePending {
		return EnrollmentPending, nil
	}
	return EnrollmentConfirmed, nil
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
	pending, err := m.storedSecretIsPending(stored)
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
	return m.storedSecretIsPending(stored)
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

	secret, pending, err := m.decodeSecret(userID, stored)
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

	hashedCodes, err := storedBackupCodes(userID, backupCodes, m.cipher)
	if err != nil {
		return nil, fmt.Errorf("failed to hash backup codes: %w", err)
	}

	// Re-encoding here also migrates a legacy plaintext row to ciphertext once a Cipher is
	// configured.
	payload, err := encodeSecret(userID, secret, false, m.cipher)
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

	secret, _, err := m.decodeSecret(userID, stored)
	if err != nil {
		return "", err
	}

	key, err := otp.NewKeyFromURL(otpauthURL(m.issuer, accountName, secret))
	if err != nil {
		return "", fmt.Errorf("failed to create key: %w", err)
	}

	return key.URL(), nil
}

// otpauthURL renders the Key-Uri-Format otpauth:// URI for a secret.
//
// Every component is escaped by net/url instead of being interpolated into a format string. An
// accountName carrying "?secret=AAAA&issuer=Attacker&x=" would otherwise close the label and
// inject query parameters, and url.Values.Get returns the FIRST value of a repeated key, so the
// injected secret and issuer are the ones an authenticator enrolls. The user then holds a factor
// the server will never accept, and the attacker holds one the user believes is theirs.
// url.URL.String percent-encodes "?" (and "#") inside the path, which is what closes that.
//
// GenerateSecret builds its URL through totp.Generate, which escapes correctly. This path is
// the same URL for the same enrollment and must not disagree with it.
func otpauthURL(issuer, accountName, secret string) string {
	query := url.Values{}
	query.Set("secret", secret)
	query.Set("issuer", issuer)

	uri := url.URL{
		Scheme: "otpauth",
		Host:   "totp",
		Path:   "/" + issuer + ":" + accountName,
		// url.Values.Encode writes a space as "+", which some authenticator apps do not
		// decode inside an otpauth URI; totp.Generate emits %20 for the same reason. Every
		// literal "+" in a value is already percent-encoded as %2B by this point, so the only
		// "+" left to rewrite is an encoded space.
		RawQuery: strings.ReplaceAll(query.Encode(), "+", "%20"),
	}
	return uri.String()
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
//
// Format: XXXX-XXXX-XXXX-XXXX, DefaultBackupCodeLength uppercase base32 characters in groups of
// backupCodeGroup. The width is the control: the stored digest is one unkeyed hash pass (see
// hashBackupCode for why it cannot be a password hash), so the only thing standing between an
// attacker holding the store and a working second factor is the cost of enumerating the code
// space. At the original 40 bits that was minutes of GPU time per user; 80 bits is not
// enumerable at any budget, which is what makes the cheap digest a defensible choice.
func generateBackupCode() (string, error) {
	b := make([]byte, backupCodeBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	code := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	if len(code) < DefaultBackupCodeLength {
		// Unreachable: base32 of backupCodeBytes is exactly DefaultBackupCodeLength characters.
		// Refuse rather than hand back a short code, which would be a silently weaker credential.
		return "", fmt.Errorf("backup code is %d characters, want %d", len(code), DefaultBackupCodeLength)
	}

	var grouped strings.Builder
	for i := 0; i < DefaultBackupCodeLength; i += backupCodeGroup {
		if i > 0 {
			grouped.WriteByte('-')
		}
		grouped.WriteString(code[i : i+backupCodeGroup])
	}
	return grouped.String(), nil
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

	secret, _, err := m.decodeSecret(userID, stored)
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
func encodeSecret(userID, secret string, pending bool, cipher Cipher) (string, error) {
	if !pending && cipher == nil {
		return secret, nil
	}

	state := secretStateActive
	if pending {
		state = secretStatePending
	}

	if cipher == nil {
		return taggedSecret(state, secretEncodingRaw, secret), nil
	}

	// What is sealed is the tagged, account-bound payload, not the bare secret: see
	// sealedSecretPlaintext.
	ciphertext, err := cipher.Encrypt([]byte(sealedSecretPlaintext(state, userID, secret)))
	if err != nil {
		return "", fmt.Errorf("encrypt TOTP secret: %w", err)
	}
	return taggedSecret(state, secretEncodingEnc, base64.StdEncoding.EncodeToString(ciphertext)), nil
}

// taggedSecret renders the payload grammar described in the package documentation.
func taggedSecret(state, encoding, data string) string {
	return secretPrefix + state + "$" + encoding + "$" + data
}

// sealedSecretPlaintext is what Config.Cipher actually encrypts:
//
//	"$gat1$" <state> "$e$" <account binding> "$" <secret>
//
// The tag must also travel in the clear, because IsEnabled answers without key material, and
// that clear copy is writable by anyone who can write to the store. Sealing a second copy under
// the cipher makes the clear one verifiable: rewriting "$gat1$a$e$<ciphertext>" to
// "$gat1$a$r$<attacker secret>", or flipping a pending enrollment to active, no longer agrees
// with what comes out of Decrypt. Cipher cannot be handed additional authenticated data
// without changing its interface, which v1 forbids, so this rides inside the plaintext and is
// compared after decrypt instead -- the same end by the means available.
//
// The binding pins the payload to one account, which the tag alone does not. Without it an
// attacker who can write to the store enrolls a factor of their own and copies their sealed row
// over the victim's: every marker agrees, the ciphertext authenticates, and the attacker's
// authenticator now passes the victim's second factor -- a complete bypass that never needs to
// downgrade anything. It is a digest of the user ID rather than the ID itself, so the sealed
// plaintext keeps a fixed, delimiter-free shape whatever the ID contains.
func sealedSecretPlaintext(state, userID, secret string) string {
	return taggedSecret(state, secretEncodingEnc, accountBinding(userID)+"$"+secret)
}

// accountBinding derives the account marker sealed into an encrypted secret. It is not secret:
// the user ID is public, and its job is to make one account's ciphertext useless in another's
// row, not to hide anything.
func accountBinding(userID string) string {
	sum := sha256.Sum256([]byte(accountBindingContext + userID))
	return hex.EncodeToString(sum[:])
}

// splitSealedSecret parses what sealedSecretPlaintext produced.
//
// Every failure here is ErrSecretTampered rather than ErrCorruptSecret: this plaintext came out
// of the cipher intact, so a shape the library never writes means the value was sealed by
// something else.
func splitSealedSecret(plaintext string) (state, binding, secret string, err error) {
	if !strings.HasPrefix(plaintext, secretPrefix) {
		return "", "", "", ErrSecretTampered
	}

	// "$gat1$a$e$BINDING$SECRET" splits into ["", "gat1", "a", "e", "BINDING", "SECRET"].
	parts := strings.SplitN(plaintext, "$", 6)
	if len(parts) != 6 {
		return "", "", "", ErrSecretTampered
	}
	state, encoding, binding, secret := parts[2], parts[3], parts[4], parts[5]
	if encoding != secretEncodingEnc || binding == "" || secret == "" {
		return "", "", "", ErrSecretTampered
	}
	return state, binding, secret, nil
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
//
// It still refuses a payload the manager's configuration says may not be read at all: a check
// that answered "active" for a downgraded row would be the gate that lets the downgrade
// through, since IsEnabled is what a caller consults before demanding a code.
func (m *Manager) storedSecretIsPending(stored string) (bool, error) {
	state, encoding, _, err := splitSecretPayload(stored)
	if err != nil {
		return false, err
	}
	if err := m.checkStoredEncoding(stored, encoding); err != nil {
		return false, err
	}
	return state == secretStatePending, nil
}

// checkStoredEncoding refuses a stored payload whose encoding is weaker than the configuration
// demands, before anything is read out of it.
//
// With a Cipher configured, an unencrypted secret in the store is either a row written before
// the Cipher existed or a downgrade written by an attacker, and the value alone cannot tell
// the two apart. Honoring encoding "r" regardless handed anyone who can write to the store a
// way to swap the sealed secret for one of their own and be believed -- precisely the adversary
// a Cipher is configured against -- so it is refused. The bare legacy shape is refused too,
// unless the caller has opened the migration window.
func (m *Manager) checkStoredEncoding(stored, encoding string) error {
	if m.cipher == nil || encoding == secretEncodingEnc {
		return nil
	}
	if strings.HasPrefix(stored, secretPrefix) {
		// This library never writes a tagged raw payload while a Cipher is configured, so no
		// migration window can account for one and the shim does not cover it.
		return ErrSecretNotEncrypted
	}
	if m.allowLegacyPlaintext {
		return nil
	}
	return ErrSecretNotEncrypted
}

// decodeSecret recovers the base32 shared secret and the enrollment state from the payload
// stored for userID.
func (m *Manager) decodeSecret(userID, stored string) (secret string, pending bool, err error) {
	state, encoding, data, err := splitSecretPayload(stored)
	if err != nil {
		return "", false, err
	}
	if encodingErr := m.checkStoredEncoding(stored, encoding); encodingErr != nil {
		return "", false, encodingErr
	}
	pending = state == secretStatePending

	if encoding == secretEncodingRaw {
		return data, pending, nil
	}

	secret, err = m.openSealedSecret(userID, state, data)
	if err != nil {
		return "", false, err
	}
	return secret, pending, nil
}

// openSealedSecret decrypts data and holds the tag sealed inside it against the tag the store
// carries in the clear. A mismatch means the payload was rewritten after the library sealed it.
func (m *Manager) openSealedSecret(userID, state, data string) (string, error) {
	if m.cipher == nil {
		return "", ErrCipherRequired
	}

	ciphertext, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrCorruptSecret, err)
	}
	plaintext, err := m.cipher.Decrypt(ciphertext)
	if err != nil {
		return "", fmt.Errorf("decrypt TOTP secret: %w", err)
	}

	sealedState, binding, secret, err := splitSealedSecret(string(plaintext))
	if err != nil {
		return "", err
	}
	// Neither value is a secret -- one is a single public character, the other a digest of a
	// public user ID -- so a constant-time compare would only suggest that they were.
	if sealedState != state || binding != accountBinding(userID) {
		return "", ErrSecretTampered
	}
	return secret, nil
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
// interface has no column for one in v1. It is not secret, and being derived from a public
// value it is not a work factor either; its job is to stop one precomputed table from covering
// every user, and to stop the identical digest of a shared code from appearing under two
// accounts.
//
// What is left carrying the weight is the width of the code itself, which is why
// DefaultBackupCodeLength is 80 bits rather than the 40 this started at: a single SHA-256 pass
// over a 40-bit space is a few minutes of one GPU, so the digest was protecting nothing an
// attacker holding the store would notice. At 80 bits the enumeration is not on the table, and
// the remaining exposure -- the digest is offline-attackable in principle -- has no budget that
// buys it. Where a deployment configures a Cipher, sealBackupCode puts the digests out of a
// store reader's reach entirely.
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

// hashBackupCodes maps generated codes to their digests.
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

// storedBackupCodes maps generated codes to the values the store receives: digests, sealed by
// the Cipher when one is configured.
//
// Without this step a deployment that configures a Cipher, reads "secrets are encrypted at
// rest" and considers F-06 closed still hands a store reader ten working second factors,
// because the digests are only as strong as the code behind them.
func storedBackupCodes(userID string, codes []string, cipher Cipher) ([]string, error) {
	stored, err := hashBackupCodes(userID, codes)
	if err != nil {
		return nil, err
	}
	if cipher == nil {
		return stored, nil
	}

	for i, digest := range stored {
		sealed, err := sealBackupCode(cipher, digest)
		if err != nil {
			return nil, err
		}
		stored[i] = sealed
	}
	return stored, nil
}

// sealBackupCode encrypts one digest for storage. The digest's own prefix goes inside the
// ciphertext, so openBackupCode can tell a value it sealed from anything else that decrypts.
func sealBackupCode(cipher Cipher, digest string) (string, error) {
	ciphertext, err := cipher.Encrypt([]byte(digest))
	if err != nil {
		return "", fmt.Errorf("encrypt backup code: %w", err)
	}
	return backupCodeSealPrefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// openBackupCode reduces one stored entry to the form a submission is compared against: a
// digest, or a legacy plaintext code. An entry that is not sealed is returned as it stands, so
// a sheet issued before the Cipher was configured keeps validating.
func openBackupCode(cipher Cipher, stored string) (string, error) {
	if !strings.HasPrefix(stored, backupCodeSealPrefix) {
		return stored, nil
	}
	if cipher == nil {
		return "", ErrCipherRequired
	}

	ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, backupCodeSealPrefix))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrCorruptSecret, err)
	}
	plaintext, err := cipher.Decrypt(ciphertext)
	if err != nil {
		return "", fmt.Errorf("decrypt backup code: %w", err)
	}
	// A sealed entry always opens to a digest. Anything else was not written here, and
	// treating it as a plaintext code would let a value that merely decrypts be compared
	// against the submission verbatim.
	if !strings.HasPrefix(string(plaintext), backupCodeHashPrefix) {
		return "", ErrSecretTampered
	}
	return string(plaintext), nil
}

// matchBackupCode finds the stored entry corresponding to the presented code and returns it
// verbatim, so the caller can hand it back to CredentialStore.UseBackupCode.
//
// The scan does not stop at the first match and never branches on a comparison result: with an
// early exit, the time to a rejection would reveal how many entries were examined, and with a
// match, which slot matched. A row written before this release is still plaintext, so both
// shapes are compared, each in constant time (F-06).
func matchBackupCode(cipher Cipher, userID, code string, storedCodes []string) (string, bool, error) {
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
	var openErr error
	for i, stored := range storedCodes {
		target, err := openBackupCode(cipher, stored)
		if err != nil {
			// Keep scanning. Abandoning the sheet at the first unreadable entry would let one
			// damaged row hide a code that does match, and would leak that row's position.
			if openErr == nil {
				openErr = err
			}
			continue
		}

		var equal int
		if strings.HasPrefix(target, backupCodeHashPrefix) {
			equal = subtle.ConstantTimeCompare([]byte(presentedHash), []byte(target))
		} else {
			equal = subtle.ConstantTimeCompare([]byte(presentedPlain), []byte(normalizeBackupCode(target)))
		}
		matchIndex = subtle.ConstantTimeSelect(equal, i, matchIndex)
	}

	if matchIndex >= 0 {
		return storedCodes[matchIndex], true, nil
	}
	if openErr != nil {
		// Nothing matched AND something could not be read: report the outage. Reporting a
		// plain "wrong code" would present a key rotation as the user's mistake, and would
		// hide it for as long as they kept retrying.
		return "", false, openErr
	}
	return "", false, nil
}
