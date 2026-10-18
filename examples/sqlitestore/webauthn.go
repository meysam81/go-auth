package sqlitestore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/meysam81/go-auth/v2/store"
	"github.com/meysam81/go-auth/v2/webauthn"
)

// WebAuthnStore is a [webauthn.CredentialStore] and a [webauthn.HandleStore]
// on the webauthn_credentials and webauthn_handles tables.
type WebAuthnStore struct {
	db *sql.DB
}

var (
	_ webauthn.CredentialStore = (*WebAuthnStore)(nil)
	_ webauthn.HandleStore     = (*WebAuthnStore)(nil)
)

// NewWebAuthnStore returns a WebAuthnStore on cfg.DB.
func NewWebAuthnStore(cfg Config) (*WebAuthnStore, error) {
	if cfg.DB == nil {
		return nil, errors.New("sqlitestore: Config.DB is required")
	}
	return &WebAuthnStore{db: cfg.DB}, nil
}

// insertCredential relies on the primary key on credential_id alone: of two
// Inserts of one ID, under any subjects and RP IDs, the second fails in the
// same statement. A SELECT first would let concurrent Inserts both pass it.
const insertCredential = `INSERT INTO webauthn_credentials (
	credential_id, subject, rp_id, version, public_key, algorithm, aaguid,
	transports, sign_count, backup_eligible, backup_state, uv_initialized,
	discoverable, created_at, last_used_at, clone_suspected_at
) VALUES (
	:credential_id, :subject, :rp_id, :version, :public_key, :algorithm, :aaguid,
	:transports, :sign_count, :backup_eligible, :backup_state, :uv_initialized,
	:discoverable, :created_at, :last_used_at, :clone_suspected_at
)`

// Insert stores c. It returns [store.ErrDuplicate] when any subject already
// holds c.ID. A zero CreatedAt, or an empty ID or public key, is refused.
func (s *WebAuthnStore) Insert(ctx context.Context, c webauthn.Credential) error {
	transports, err := encodeTransports(c.Transports)
	if err != nil {
		return fmt.Errorf("sqlitestore: insert credential: %w", err)
	}
	var discoverable sql.NullBool
	if c.Discoverable != nil {
		discoverable = sql.NullBool{Bool: *c.Discoverable, Valid: true}
	}
	_, err = s.db.ExecContext(ctx, insertCredential,
		sql.Named("credential_id", c.ID),
		sql.Named("subject", c.Subject),
		sql.Named("rp_id", c.RPID),
		sql.Named("version", int64(c.Version)),
		sql.Named("public_key", c.PublicKey),
		sql.Named("algorithm", int64(c.Algorithm)),
		sql.Named("aaguid", c.AAGUID[:]),
		sql.Named("transports", transports),
		sql.Named("sign_count", int64(c.SignCount)),
		sql.Named("backup_eligible", c.BackupEligible),
		sql.Named("backup_state", c.BackupState),
		sql.Named("uv_initialized", c.UVInitialized),
		sql.Named("discoverable", discoverable),
		sql.Named("created_at", timeArg(c.CreatedAt)),
		sql.Named("last_used_at", timeArg(c.LastUsedAt)),
		sql.Named("clone_suspected_at", timeArg(c.CloneSuspectedAt)))
	switch {
	case primaryKeyViolation(err):
		return fmt.Errorf("sqlitestore: insert credential: %w: %w", store.ErrDuplicate, err)
	case err != nil:
		return fmt.Errorf("sqlitestore: insert credential: %w", err)
	}
	return nil
}

//nolint:gosec // G101: a query, not a credential
const listCredentials = `SELECT
	credential_id, subject, rp_id, version, public_key, algorithm, aaguid,
	transports, sign_count, backup_eligible, backup_state, uv_initialized,
	discoverable, created_at, last_used_at, clone_suspected_at
FROM webauthn_credentials
WHERE subject = :subject AND rp_id = :rp_id
ORDER BY created_at, credential_id`

// List returns the subject's credentials for rpID, oldest first. Every time
// is in UTC, and an empty Transports is nil.
func (s *WebAuthnStore) List(ctx context.Context, subject, rpID string) (creds []webauthn.Credential, err error) {
	rows, err := s.db.QueryContext(ctx, listCredentials,
		sql.Named("subject", subject),
		sql.Named("rp_id", rpID))
	if err != nil {
		return nil, fmt.Errorf("sqlitestore: list credentials: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			creds, err = nil, errors.Join(err, fmt.Errorf("sqlitestore: list credentials: %w", closeErr))
		}
	}()
	for rows.Next() {
		c, scanErr := scanCredential(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("sqlitestore: list credentials: %w", scanErr)
		}
		creds = append(creds, c)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlitestore: list credentials: %w", err)
	}
	return creds, nil
}

// scanCredential reads one row of listCredentials. database/sql refuses an
// integer outside the Go field's range (a sign_count above 2^32-1, a version
// above 2^16-1) and a boolean column holding anything but 0 or 1.
func scanCredential(rows *sql.Rows) (webauthn.Credential, error) {
	var (
		c                                 webauthn.Credential
		aaguid                            []byte
		transports                        string
		discoverable                      sql.NullBool
		created, lastUsed, cloneSuspected sql.NullInt64
	)
	if err := rows.Scan(
		&c.ID, &c.Subject, &c.RPID, &c.Version, &c.PublicKey, &c.Algorithm, &aaguid,
		&transports, &c.SignCount, &c.BackupEligible, &c.BackupState, &c.UVInitialized,
		&discoverable, &created, &lastUsed, &cloneSuspected,
	); err != nil {
		return webauthn.Credential{}, err
	}
	if len(aaguid) != len(c.AAGUID) {
		return webauthn.Credential{}, fmt.Errorf("credential aaguid of %d bytes, want %d", len(aaguid), len(c.AAGUID))
	}
	copy(c.AAGUID[:], aaguid)
	if err := json.Unmarshal([]byte(transports), &c.Transports); err != nil {
		return webauthn.Credential{}, fmt.Errorf("credential transports: %w", err)
	}
	if len(c.Transports) == 0 {
		c.Transports = nil
	}
	if discoverable.Valid {
		c.Discoverable = &discoverable.Bool
	}
	c.CreatedAt = timeOf(created)
	c.LastUsedAt = timeOf(lastUsed)
	c.CloneSuspectedAt = timeOf(cloneSuspected)
	return c, nil
}

// encodeTransports returns ts as a JSON array, "[]" for none: json.Marshal
// writes a nil slice as null, which the column's CHECK refuses.
func encodeTransports(ts []string) (string, error) {
	if ts == nil {
		ts = []string{}
	}
	b, err := json.Marshal(ts)
	if err != nil {
		return "", fmt.Errorf("transports: %w", err)
	}
	return string(b), nil
}

// recordAssertion is the conditional update the CredentialStore contract
// spells out. The sign_count predicate is the compare-and-swap: of concurrent
// assertions read at one counter, the first UPDATE moves it and the rest
// match nothing. The credential_id predicate keeps a sibling credential with
// the same counter (synced passkeys all count zero) out of the write.
const recordAssertion = `UPDATE webauthn_credentials SET
	sign_count = :sign_count,
	backup_eligible = :backup_eligible,
	backup_state = :backup_state,
	version = :version,
	last_used_at = :last_used_at
WHERE subject = :subject AND credential_id = :credential_id AND sign_count = :prev_sign_count`

// RecordAssertion applies u only while the stored counter still equals
// u.PrevSignCount. applied is false when no row matched: the counter moved,
// or no credential of u.Subject has the ID.
func (s *WebAuthnStore) RecordAssertion(ctx context.Context, u webauthn.AssertionUpdate) (applied bool, err error) {
	res, err := s.db.ExecContext(ctx, recordAssertion,
		sql.Named("sign_count", int64(u.SignCount)),
		sql.Named("backup_eligible", u.BackupEligible),
		sql.Named("backup_state", u.BackupState),
		sql.Named("version", int64(u.Version)),
		sql.Named("last_used_at", timeArg(u.At)),
		sql.Named("subject", u.Subject),
		sql.Named("credential_id", u.CredentialID),
		sql.Named("prev_sign_count", int64(u.PrevSignCount)))
	if err != nil {
		return false, fmt.Errorf("sqlitestore: record assertion: %w", err)
	}
	n, err := oneRow(res)
	if err != nil {
		return false, fmt.Errorf("sqlitestore: record assertion: %w", err)
	}
	return n == 1, nil
}

const markCloneSuspected = `UPDATE webauthn_credentials SET clone_suspected_at = :at
WHERE subject = :subject AND credential_id = :credential_id`

// MarkCloneSuspected sets the credential's CloneSuspectedAt to at. It returns
// [store.ErrNotFound] when the subject holds no credential with the ID, and
// refuses a zero at: the zero time is stored as NULL, "not suspected", so it
// would clear a mark instead of setting one.
func (s *WebAuthnStore) MarkCloneSuspected(ctx context.Context, subject string, id []byte, at time.Time) error {
	if at.IsZero() {
		return errors.New("sqlitestore: mark clone suspected: zero time")
	}
	res, err := s.db.ExecContext(ctx, markCloneSuspected,
		sql.Named("at", timeArg(at)),
		sql.Named("subject", subject),
		sql.Named("credential_id", id))
	if err != nil {
		return fmt.Errorf("sqlitestore: mark clone suspected: %w", err)
	}
	n, err := oneRow(res)
	if err != nil {
		return fmt.Errorf("sqlitestore: mark clone suspected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("sqlitestore: mark clone suspected: %w", store.ErrNotFound)
	}
	return nil
}

// oneRow returns the rows res affected, which an update keyed on the primary
// key keeps to 0 or 1; any other count is an error.
func oneRow(res sql.Result) (int64, error) {
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	if n != 0 && n != 1 {
		return 0, fmt.Errorf("%d rows affected, want 0 or 1", n)
	}
	return n, nil
}

// ensureHandle stores the proposed handle unless the subject has one, and
// returns the subject's handle either way, in one statement: concurrent
// callers all get the handle of the first. The no-op DO UPDATE is what makes
// RETURNING yield the existing row; DO NOTHING would return no row on a
// conflict and need a second, racing SELECT. The upsert covers the subject
// key only, so a proposed handle another subject holds still fails, on the
// handle's own unique index. PostgreSQL runs the statement as written.
const ensureHandle = `INSERT INTO webauthn_handles (subject, handle) VALUES (:subject, :handle)
ON CONFLICT (subject) DO UPDATE SET handle = webauthn_handles.handle
RETURNING handle`

// Ensure returns the subject's handle, storing h first when it has none. It
// returns [store.ErrDuplicate] when another subject holds h.
func (s *WebAuthnStore) Ensure(ctx context.Context, subject string, h []byte) ([]byte, error) {
	var handle []byte
	err := s.db.QueryRowContext(ctx, ensureHandle,
		sql.Named("subject", subject),
		sql.Named("handle", h)).
		Scan(&handle)
	switch {
	case uniqueViolation(err):
		return nil, fmt.Errorf("sqlitestore: ensure handle: %w: %w", store.ErrDuplicate, err)
	case err != nil:
		return nil, fmt.Errorf("sqlitestore: ensure handle: %w", err)
	}
	return handle, nil
}

const subjectByHandle = `SELECT subject FROM webauthn_handles WHERE handle = :handle`

// Subject returns the subject holding handle, or [store.ErrNotFound]. Handles
// compare byte for byte: a prefix or an extension of a handle is another one.
func (s *WebAuthnStore) Subject(ctx context.Context, handle []byte) (string, error) {
	var subject string
	err := s.db.QueryRowContext(ctx, subjectByHandle, sql.Named("handle", handle)).Scan(&subject)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", fmt.Errorf("sqlitestore: subject by handle: %w", store.ErrNotFound)
	case err != nil:
		return "", fmt.Errorf("sqlitestore: subject by handle: %w", err)
	}
	return subject, nil
}
