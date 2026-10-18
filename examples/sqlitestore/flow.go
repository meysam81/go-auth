package sqlitestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/meysam81/go-auth/v2/store"
)

// FlowStore is a [store.FlowStore] on the flows table.
type FlowStore struct {
	db  *sql.DB
	now func() time.Time
}

var _ store.FlowStore = (*FlowStore)(nil)

// NewFlowStore returns a FlowStore on cfg.DB.
func NewFlowStore(cfg Config) (*FlowStore, error) {
	if cfg.DB == nil {
		return nil, errors.New("sqlitestore: Config.DB is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &FlowStore{db: cfg.DB, now: cfg.Now}, nil
}

// putFlow inserts and never upserts: the primary key refuses an id any row
// holds, in the same statement, so of two concurrent Puts one fails and
// neither overwrites the other.
const putFlow = `INSERT INTO flows (id, kind, payload, expires_at)
VALUES (:id, :kind, :payload, :expires_at)`

// Put stores f under id. It returns [store.ErrDuplicate] when a row already
// holds id, consumed or not, and leaves that row untouched. A zero ExpiresAt
// is refused.
func (s *FlowStore) Put(ctx context.Context, id string, f store.Flow) error {
	payload := f.Payload
	if payload == nil {
		payload = []byte{} // a nil []byte binds as NULL; an empty payload is an empty BLOB
	}
	_, err := s.db.ExecContext(ctx, putFlow,
		sql.Named("id", id),
		sql.Named("kind", f.Kind),
		sql.Named("payload", payload),
		sql.Named("expires_at", timeArg(f.ExpiresAt)))
	switch {
	case primaryKeyViolation(err):
		return fmt.Errorf("sqlitestore: put flow: %w: %w", store.ErrDuplicate, err)
	case err != nil:
		return fmt.Errorf("sqlitestore: put flow: %w", err)
	}
	return nil
}

// takeFlow consumes and reads the flow in one statement, and its WHERE clause
// is the whole single-use rule. SQLite runs one writer at a time; of
// concurrent Takes, the first UPDATE matches the row and the rest find
// used_at set and match nothing. A SELECT before the UPDATE would let every
// caller see the flow unused. On a database without UPDATE ... RETURNING,
// run the UPDATE alone, check that it affected one row, then SELECT the
// columns: only the caller that consumed the row reads it.
const takeFlow = `UPDATE flows SET used_at = :now
WHERE id = :id AND used_at IS NULL AND expires_at > :now
RETURNING kind, payload, expires_at`

// Take consumes the flow and returns it. A missing, expired or consumed flow
// is [store.ErrNotFound] alike: one statement decides all three, so neither
// the error nor the work done tells them apart.
func (s *FlowStore) Take(ctx context.Context, id string) (store.Flow, error) {
	var (
		f         store.Flow
		expiresAt int64
	)
	err := s.db.QueryRowContext(ctx, takeFlow,
		sql.Named("id", id),
		sql.Named("now", s.now().UnixMicro())).
		Scan(&f.Kind, &f.Payload, &expiresAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return store.Flow{}, fmt.Errorf("sqlitestore: take flow: %w", store.ErrNotFound)
	case err != nil:
		return store.Flow{}, fmt.Errorf("sqlitestore: take flow: %w", err)
	}
	f.ExpiresAt = time.UnixMicro(expiresAt).UTC()
	return f, nil
}
