package authtest

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/meysam81/go-auth/v2/store"
)

// FlowStoreSuite returns a test that proves a [store.FlowStore]. Run it from
// your own test against your database-backed store:
//
//	func TestFlowStore(t *testing.T) {
//		authtest.FlowStoreSuite(func(t *testing.T) store.FlowStore { return newSQLFlowStore(t) })(t)
//	}
//
// newStore is called once per subtest and must return a store no other
// subtest has written to (a fresh table or schema is the usual way). Each
// subtest is a rule from the storage contract; a failure names the rule.
func FlowStoreSuite(newStore func(t *testing.T) store.FlowStore) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()
		ctx := t.Context()
		// The subtests run in sequence: an application's newStore may reset a
		// shared database, so independence is not assumed.
		future := func() time.Time { return time.Now().Add(time.Hour).Truncate(time.Second).UTC() }

		t.Run("PutThenTake", func(t *testing.T) {
			s := newStore(t)
			want := store.Flow{Kind: "k", Payload: []byte("payload"), ExpiresAt: future()}
			if err := s.Put(ctx, "id-1", want); err != nil {
				t.Fatalf("Put: %v", err)
			}
			got, err := s.Take(ctx, "id-1")
			if err != nil {
				t.Fatalf("Take: %v", err)
			}
			if got.Kind != want.Kind || !bytes.Equal(got.Payload, want.Payload) || !got.ExpiresAt.Equal(want.ExpiresAt) {
				t.Fatalf("Take = %+v, want %+v", got, want)
			}
		})

		t.Run("SecondTakeIsNotFound", func(t *testing.T) {
			s := newStore(t)
			if err := s.Put(ctx, "id-1", store.Flow{Kind: "k", Payload: []byte("p"), ExpiresAt: future()}); err != nil {
				t.Fatalf("Put: %v", err)
			}
			if _, err := s.Take(ctx, "id-1"); err != nil {
				t.Fatalf("first Take: %v", err)
			}
			if _, err := s.Take(ctx, "id-1"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("second Take error = %v, want store.ErrNotFound (a flow is single-use)", err)
			}
		})

		t.Run("ExpiredIsNotFound", func(t *testing.T) {
			s := newStore(t)
			expired := store.Flow{Kind: "k", Payload: []byte("p"), ExpiresAt: time.Now().Add(-time.Hour)}
			if err := s.Put(ctx, "id-1", expired); err != nil {
				t.Fatalf("Put: %v", err)
			}
			if _, err := s.Take(ctx, "id-1"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("Take of an expired flow error = %v, want store.ErrNotFound", err)
			}
		})

		t.Run("UnknownIsNotFound", func(t *testing.T) {
			s := newStore(t)
			if _, err := s.Take(ctx, "never-stored"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("Take of an unknown id error = %v, want store.ErrNotFound", err)
			}
		})

		t.Run("ConcurrentTake_OneWinner", func(t *testing.T) {
			s := newStore(t)
			if err := s.Put(ctx, "id-1", store.Flow{Kind: "k", Payload: []byte("p"), ExpiresAt: future()}); err != nil {
				t.Fatalf("Put: %v", err)
			}
			const callers = 32
			var wg sync.WaitGroup
			var won, notFound, other atomic.Int32
			start := make(chan struct{})
			for range callers {
				wg.Go(func() {
					<-start
					switch _, err := s.Take(ctx, "id-1"); {
					case err == nil:
						won.Add(1)
					case errors.Is(err, store.ErrNotFound):
						notFound.Add(1)
					default:
						other.Add(1)
					}
				})
			}
			close(start)
			wg.Wait()
			if won.Load() != 1 || notFound.Load() != callers-1 || other.Load() != 0 {
				t.Fatalf("%d Takes: %d won, %d ErrNotFound, %d other errors; want exactly 1, %d, 0 (Take must be one atomic consume, not Get then Delete)",
					callers, won.Load(), notFound.Load(), other.Load(), callers-1)
			}
		})

		t.Run("RoundTripsEveryField", func(t *testing.T) {
			s := newStore(t)
			var want store.Flow
			FillNonZero(t, &want)
			want.Payload = []byte{0x00, 0x01, 0xff, 0x7f, 0x00, 0xfe, 0xff}
			want.ExpiresAt = future() // FillNonZero's instant may be in the past
			if err := s.Put(ctx, "id-1", want); err != nil {
				t.Fatalf("Put: %v", err)
			}
			got, err := s.Take(ctx, "id-1")
			if err != nil {
				t.Fatalf("Take: %v", err)
			}
			if field := diffFields(got, want); field != "" {
				t.Fatalf("field %s did not round-trip: got %+v, want %+v", field, got, want)
			}
		})
	}
}
