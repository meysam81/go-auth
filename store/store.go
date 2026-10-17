package store

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned by [FlowStore.Take] when no usable flow exists for
// the id. Missing, expired and already-consumed flows are indistinguishable by
// design.
var ErrNotFound = errors.New("store: not found")

// ErrDuplicate is returned when a write would create a second record under a
// key that must be unique, such as a flow id or a credential id.
var ErrDuplicate = errors.New("store: duplicate")

// Flow is ceremony state the application persists without interpreting.
type Flow struct {
	Kind      string    // which ceremony wrote it; the reader checks it
	Payload   []byte    // library-owned encoding
	ExpiresAt time.Time // the store refuses to return an expired flow
}

// FlowStore holds single-use ceremony state.
type FlowStore interface {
	// Put stores the flow under id.
	Put(ctx context.Context, id string, f Flow) error

	// Take fetches and consumes atomically. It MUST NOT be a Get followed by a
	// Delete: on a READ COMMITTED database two concurrent callers would both
	// observe the flow unused and both succeed. The SQL shape is
	//   UPDATE flows SET used_at = ? WHERE id = ? AND used_at IS NULL AND expires_at > ?
	// checking the affected-row count. Returning ErrNotFound for missing,
	// expired and already-consumed alike is required: the difference is an oracle.
	Take(ctx context.Context, id string) (Flow, error)
}
