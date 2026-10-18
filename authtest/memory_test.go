package authtest_test

import (
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/meysam81/go-auth/v2/authtest"
	"github.com/meysam81/go-auth/v2/store"
	"github.com/meysam81/go-auth/v2/webauthn"
)

var subjectSeq atomic.Int64

func TestMemoryStores_PassSuites(t *testing.T) {
	t.Parallel()
	flowSuite := authtest.FlowStoreSuite(func(*testing.T) store.FlowStore {
		return authtest.NewMemoryFlowStore(nil)
	})
	t.Run("FlowStore", func(t *testing.T) {
		t.Parallel()
		flowSuite(t)
	})
	webauthnSuite := authtest.WebAuthnStoreSuite(authtest.WebAuthnHarness{
		NewStores: func(*testing.T) (webauthn.CredentialStore, webauthn.HandleStore) {
			m := authtest.NewMemoryWebAuthnStore()
			return m, m
		},
		NewSubject: func(*testing.T) string { return fmt.Sprintf("subject-%d", subjectSeq.Add(1)) },
	})
	t.Run("WebAuthnStore", func(t *testing.T) {
		t.Parallel()
		webauthnSuite(t)
	})
}

func TestMemoryFlowStore_InjectedClockExpiresAndDropsEntry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := authtest.NewMemoryFlowStore(func() time.Time { return now })
	ctx := t.Context()
	if err := s.Put(ctx, "id", store.Flow{Kind: "k", ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute) // expiry is exclusive: at ExpiresAt the flow is gone
	if _, err := s.Take(ctx, "id"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Take at ExpiresAt error = %v, want store.ErrNotFound", err)
	}
	now = now.Add(-time.Hour) // the clock going back must not resurrect the entry
	if _, err := s.Take(ctx, "id"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired entry survived its failed Take: error = %v", err)
	}
}

func TestMemoryFlowStore_DeepCopies(t *testing.T) {
	t.Parallel()
	s := authtest.NewMemoryFlowStore(nil)
	ctx := t.Context()
	payload := []byte{1, 2, 3}
	if err := s.Put(ctx, "id", store.Flow{Payload: payload, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	payload[0] = 9 // the caller edits its own slice after Put
	got, err := s.Take(ctx, "id")
	if err != nil {
		t.Fatal(err)
	}
	if got.Payload[0] != 1 {
		t.Fatalf("stored payload changed through the caller's slice: %v", got.Payload)
	}
}

func TestMemoryWebAuthnStore_DeepCopies(t *testing.T) {
	t.Parallel()
	m := authtest.NewMemoryWebAuthnStore()
	ctx := t.Context()
	yes := true
	in := webauthn.Credential{
		ID: []byte{1, 2}, Subject: "s", RPID: "rp", PublicKey: []byte{3, 4},
		Transports: []string{"usb"}, Discoverable: &yes,
	}
	if err := m.Insert(ctx, in); err != nil {
		t.Fatal(err)
	}
	in.ID[0], in.PublicKey[0], in.Transports[0], *in.Discoverable = 9, 9, "nfc", false // after Insert

	out, err := m.List(ctx, "s", "rp")
	if err != nil || len(out) != 1 {
		t.Fatalf("List = %v, %v", out, err)
	}
	if out[0].ID[0] != 1 || out[0].PublicKey[0] != 3 || out[0].Transports[0] != "usb" || !*out[0].Discoverable {
		t.Fatalf("Insert shared memory with the caller: %+v", out[0])
	}
	out[0].ID[0], out[0].PublicKey[0], out[0].Transports[0], *out[0].Discoverable = 7, 7, "ble", false // after List

	again, err := m.List(ctx, "s", "rp")
	if err != nil || len(again) != 1 {
		t.Fatalf("List = %v, %v", again, err)
	}
	if again[0].ID[0] != 1 || again[0].PublicKey[0] != 3 || again[0].Transports[0] != "usb" || !*again[0].Discoverable {
		t.Fatalf("List shared memory with the caller: %+v", again[0])
	}

	h := []byte{5, 6}
	got, err := m.Ensure(ctx, "s", h)
	if err != nil {
		t.Fatal(err)
	}
	h[0], got[1] = 0, 0
	handleAgain, err := m.Ensure(ctx, "s", []byte{1})
	if err != nil || handleAgain[0] != 5 || handleAgain[1] != 6 {
		t.Fatalf("Ensure shared memory with the caller: %v, %v", handleAgain, err)
	}
}

func TestMemoryWebAuthnStore_Delete(t *testing.T) {
	t.Parallel()
	m := authtest.NewMemoryWebAuthnStore()
	ctx := t.Context()
	c := webauthn.Credential{ID: []byte{1}, Subject: "s", RPID: "rp"}
	if err := m.Insert(ctx, c); err != nil {
		t.Fatal(err)
	}
	m.Delete("other", c.ID) // wrong subject: no effect
	got, err := m.List(ctx, "s", "rp")
	if err != nil || len(got) != 1 {
		t.Fatalf("Delete for another subject removed the credential: %v, %v", got, err)
	}
	m.Delete("s", c.ID)
	got, err = m.List(ctx, "s", "rp")
	if err != nil || len(got) != 0 {
		t.Fatalf("Delete left the credential: %v, %v", got, err)
	}
}

type fillProbe struct {
	S  string
	B  []byte
	N  int
	U  uint32
	F  bool
	A  [16]byte
	TS []string
	P  *bool
	T  time.Time
}

func TestFillNonZero_SetsEveryFieldDistinct(t *testing.T) {
	t.Parallel()
	var p fillProbe
	authtest.FillNonZero(t, &p)
	if p.S == "" || len(p.B) == 0 || p.N == 0 || p.U == 0 || !p.F || p.A == [16]byte{} ||
		len(p.TS) == 0 || p.P == nil || !*p.P || p.T.IsZero() || p.T.Location() != time.UTC || p.T.Nanosecond() != 0 {
		t.Fatalf("a field was left zero: %+v", p)
	}
	if p.N == int(p.U) {
		t.Fatalf("values are not distinct: %+v", p)
	}
}

func TestMemoryFlowStore_PutExistingIDIsDuplicate(t *testing.T) {
	t.Parallel()
	s := authtest.NewMemoryFlowStore(nil)
	ctx := t.Context()
	f := store.Flow{Kind: "k", ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.Put(ctx, "id", f); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, "id", f); !errors.Is(err, store.ErrDuplicate) {
		t.Fatalf("second Put error = %v, want store.ErrDuplicate", err)
	}
}

func TestMemoryWebAuthnStore_ZeroValueAndForeignPaths(t *testing.T) {
	t.Parallel()
	var m authtest.MemoryWebAuthnStore // the zero value is usable
	ctx := t.Context()
	if _, err := m.Subject(ctx, []byte{1}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Subject on a zero store error = %v, want store.ErrNotFound", err)
	}
	if _, err := m.Ensure(ctx, "a", []byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Ensure(ctx, "b", []byte{1}); !errors.Is(err, store.ErrDuplicate) {
		t.Fatalf("Ensure of a handle another subject holds error = %v, want store.ErrDuplicate", err)
	}
	if err := m.MarkCloneSuspected(ctx, "a", []byte{9}, time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("MarkCloneSuspected of an unknown credential error = %v, want store.ErrNotFound", err)
	}
}

type namedString string

type fillNamed struct {
	Tags    []namedString
	private int //nolint:unused // proves FillNonZero and diffFields skip unexported fields
}

func TestFillNonZero_NamedStringSlice(t *testing.T) {
	t.Parallel()
	var p fillNamed
	authtest.FillNonZero(t, &p)
	if len(p.Tags) != 2 || p.Tags[0] == "" {
		t.Fatalf("named string slice not filled: %+v", p)
	}
}
