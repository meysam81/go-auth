-- Schema of the reference SQLite store. Migrate applies it; every statement is
-- IF NOT EXISTS, so applying it again changes nothing.
--
-- Every table is STRICT: a value of the wrong type is refused, never coerced.
-- The CHECK constraints spell out the rest of the storage contract, so a reader
-- porting the schema sees what each column must hold.
--
-- Times are INTEGER microseconds since the Unix epoch: UTC by definition, at a
-- fixed precision. NULL is the zero time.Time ("never") and is allowed only
-- where "never" means something.

-- Single-use ceremony state (store.FlowStore). A row stays after Take marks it
-- used; the application deletes consumed and expired rows on its own schedule.
CREATE TABLE IF NOT EXISTS flows (
    -- BINARY collation compares the id byte for byte; a case-insensitive
    -- collation would let a case variant of the id consume the flow.
    id         TEXT    NOT NULL PRIMARY KEY COLLATE BINARY CHECK (length(id) > 0),
    kind       TEXT    NOT NULL,
    payload    BLOB    NOT NULL CHECK (typeof(payload) = 'blob'),
    expires_at INTEGER NOT NULL,
    used_at    INTEGER -- NULL until Take consumes the flow
) STRICT;

-- One WebAuthn user handle per subject (webauthn.HandleStore). Both columns are
-- unique: a handle resolves to exactly one subject.
CREATE TABLE IF NOT EXISTS webauthn_handles (
    subject TEXT NOT NULL PRIMARY KEY,
    handle  BLOB NOT NULL UNIQUE
        CHECK (typeof(handle) = 'blob' AND length(handle) BETWEEN 1 AND 64)
) STRICT;

-- WebAuthn credentials (webauthn.CredentialStore). The primary key is the
-- credential ID alone, not (subject, credential_id): one ID is held by at most
-- one subject, whatever the RP ID.
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    credential_id      BLOB    NOT NULL PRIMARY KEY
        CHECK (typeof(credential_id) = 'blob' AND length(credential_id) BETWEEN 1 AND 1023),
    subject            TEXT    NOT NULL,
    rp_id              TEXT    NOT NULL,
    version            INTEGER NOT NULL CHECK (version BETWEEN 0 AND 65535),
    public_key         BLOB    NOT NULL
        CHECK (typeof(public_key) = 'blob' AND length(public_key) > 0),
    algorithm          INTEGER NOT NULL,
    aaguid             BLOB    NOT NULL CHECK (typeof(aaguid) = 'blob' AND length(aaguid) = 16),
    -- A JSON array of strings; '[]' when the client reported none.
    transports         TEXT    NOT NULL
        CHECK (json_valid(transports) AND json_type(transports) = 'array'),
    -- The full unsigned 32-bit range: a signed 32-bit column overflows at 2^31.
    sign_count         INTEGER NOT NULL CHECK (sign_count BETWEEN 0 AND 4294967295),
    backup_eligible    INTEGER NOT NULL CHECK (backup_eligible IN (0, 1)),
    backup_state       INTEGER NOT NULL CHECK (backup_state IN (0, 1)),
    uv_initialized     INTEGER NOT NULL CHECK (uv_initialized IN (0, 1)),
    discoverable       INTEGER CHECK (discoverable IN (0, 1)), -- NULL: not reported
    created_at         INTEGER NOT NULL,
    last_used_at       INTEGER, -- NULL: never used
    clone_suspected_at INTEGER  -- NULL: not suspected
) STRICT;

CREATE INDEX IF NOT EXISTS webauthn_credentials_subject_rp_id
    ON webauthn_credentials (subject, rp_id);
