package authtest

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/meysam81/go-auth/v2/store"
	"github.com/meysam81/go-auth/v2/webauthn"
)

// WebAuthnHarness connects [WebAuthnStoreSuite] to an application's stores.
type WebAuthnHarness struct {
	// NewStores returns stores no other subtest has written to.
	NewStores func(t *testing.T) (webauthn.CredentialStore, webauthn.HandleStore)
	// NewSubject returns a subject the application's store accepts, for
	// example the key of a freshly inserted user row when credentials hold a
	// foreign key to users. The suite draws every subject from it.
	NewSubject func(t *testing.T) string
}

// WebAuthnStoreSuite returns a test that proves a [webauthn.CredentialStore]
// and [webauthn.HandleStore]. Each subtest is a contract the application's
// SQL must meet, including the conditional RecordAssertion update and the
// credential-ID uniqueness across subjects.
func WebAuthnStoreSuite(h WebAuthnHarness) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()
		ctx := t.Context()
		const rpID = "example.test"
		t0 := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		t1 := t0.Add(48 * time.Hour)

		// newCred is a credential with every field non-zero, then pinned to
		// the values the tests reason about.
		newCred := func(t *testing.T, subject, rp string, id byte) webauthn.Credential {
			t.Helper()
			var c webauthn.Credential
			FillNonZero(t, &c)
			c.Subject, c.RPID = subject, rp
			c.ID = bytes.Repeat([]byte{id}, 16)
			c.Version = 1
			c.SignCount = 5
			c.BackupEligible, c.BackupState = false, false
			c.CreatedAt, c.LastUsedAt = t0, t0
			c.CloneSuspectedAt = time.Time{}
			return c
		}
		insert := func(t *testing.T, cs webauthn.CredentialStore, c webauthn.Credential) {
			t.Helper()
			if err := cs.Insert(ctx, c); err != nil {
				t.Fatalf("Insert: %v", err)
			}
		}
		list := func(t *testing.T, cs webauthn.CredentialStore, subject string) []webauthn.Credential {
			t.Helper()
			got, err := cs.List(ctx, subject, rpID)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			return got
		}
		// only lists the subject's single credential.
		only := func(t *testing.T, cs webauthn.CredentialStore, subject string) webauthn.Credential {
			t.Helper()
			got := list(t, cs, subject)
			if len(got) != 1 {
				t.Fatalf("List returned %d credentials, want 1", len(got))
			}
			return got[0]
		}
		assertSame := func(t *testing.T, got, want webauthn.Credential, why string) {
			t.Helper()
			if field := diffFields(got, want); field != "" {
				t.Fatalf("%s: field %s differs: got %+v, want %+v", why, field, got, want)
			}
		}
		update := func(c webauthn.Credential) webauthn.AssertionUpdate {
			return webauthn.AssertionUpdate{
				Subject: c.Subject, CredentialID: c.ID, PrevSignCount: c.SignCount,
				SignCount: c.SignCount + 4, BackupEligible: true, BackupState: true,
				Version: webauthn.CurrentVersion, At: t1,
			}
		}

		t.Run("InsertThenList", func(t *testing.T) {
			cs, _ := h.NewStores(t)
			subject := h.NewSubject(t)
			a, b := newCred(t, subject, rpID, 1), newCred(t, subject, rpID, 2)
			insert(t, cs, a)
			insert(t, cs, b)
			got := list(t, cs, subject)
			if len(got) != 2 {
				t.Fatalf("List returned %d credentials, want 2", len(got))
			}
			for _, want := range []*webauthn.Credential{&a, &b} {
				found := false
				for i := range got {
					if bytes.Equal(got[i].ID, want.ID) {
						found = true
						assertSame(t, got[i], *want, "listed credential")
					}
				}
				if !found {
					t.Fatalf("credential %x missing from List", want.ID)
				}
			}
		})

		t.Run("DuplicateIDSameSubject_ErrDuplicate", func(t *testing.T) {
			cs, _ := h.NewStores(t)
			subject := h.NewSubject(t)
			c := newCred(t, subject, rpID, 1)
			insert(t, cs, c)
			if err := cs.Insert(ctx, c); !errors.Is(err, store.ErrDuplicate) {
				t.Fatalf("second Insert error = %v, want store.ErrDuplicate", err)
			}
		})

		t.Run("DuplicateIDOtherSubject_ErrDuplicate", func(t *testing.T) {
			cs, _ := h.NewStores(t)
			owner, intruder := h.NewSubject(t), h.NewSubject(t)
			c := newCred(t, owner, rpID, 1)
			insert(t, cs, c)
			stolen := newCred(t, intruder, rpID, 1) // same credential ID, other subject
			if err := cs.Insert(ctx, stolen); !errors.Is(err, store.ErrDuplicate) {
				t.Fatalf("Insert of an ID another subject holds: error = %v, want store.ErrDuplicate (the unique index is on the credential ID alone)", err)
			}
			if got := list(t, cs, intruder); len(got) != 0 {
				t.Fatalf("the refused credential was stored for the other subject: %+v", got)
			}
			assertSame(t, only(t, cs, owner), c, "the owner's credential")
		})

		t.Run("ListFiltersByRPID", func(t *testing.T) {
			cs, _ := h.NewStores(t)
			subject := h.NewSubject(t)
			here, there := newCred(t, subject, rpID, 1), newCred(t, subject, "other.test", 2)
			insert(t, cs, here)
			insert(t, cs, there)
			assertSame(t, only(t, cs, subject), here, "credential for the asked RP ID")
		})

		t.Run("ListOtherSubjectIsEmpty", func(t *testing.T) {
			cs, _ := h.NewStores(t)
			owner, other := h.NewSubject(t), h.NewSubject(t)
			insert(t, cs, newCred(t, owner, rpID, 1))
			if got := list(t, cs, other); len(got) != 0 {
				t.Fatalf("List for a subject with no credentials returned %+v", got)
			}
		})

		t.Run("RecordAssertion_Applies", func(t *testing.T) {
			cs, _ := h.NewStores(t)
			subject := h.NewSubject(t)
			c := newCred(t, subject, rpID, 1)
			insert(t, cs, c)
			u := update(c)
			applied, err := cs.RecordAssertion(ctx, u)
			if err != nil || !applied {
				t.Fatalf("RecordAssertion = (%v, %v), want (true, nil)", applied, err)
			}
			want := c
			want.SignCount, want.BackupEligible, want.BackupState = u.SignCount, u.BackupEligible, u.BackupState
			want.Version, want.LastUsedAt = u.Version, u.At
			// Comparing the whole credential also proves nothing else moved.
			assertSame(t, only(t, cs, subject), want, "credential after an applied assertion")
		})

		t.Run("RecordAssertion_StaleCounter_NotApplied", func(t *testing.T) {
			cs, _ := h.NewStores(t)
			subject := h.NewSubject(t)
			c := newCred(t, subject, rpID, 1)
			insert(t, cs, c)
			u := update(c)
			u.PrevSignCount = c.SignCount - 1 // the counter moved since the library read it
			applied, err := cs.RecordAssertion(ctx, u)
			if err != nil || applied {
				t.Fatalf("RecordAssertion with a stale counter = (%v, %v), want (false, nil)", applied, err)
			}
			assertSame(t, only(t, cs, subject), c, "credential after a stale assertion")
		})

		t.Run("RecordAssertion_WrongSubject_NotApplied", func(t *testing.T) {
			cs, _ := h.NewStores(t)
			owner, other := h.NewSubject(t), h.NewSubject(t)
			c := newCred(t, owner, rpID, 1)
			insert(t, cs, c)
			u := update(c)
			u.Subject = other // right credential ID, wrong subject
			applied, err := cs.RecordAssertion(ctx, u)
			if err != nil || applied {
				t.Fatalf("RecordAssertion for another subject = (%v, %v), want (false, nil)", applied, err)
			}
			assertSame(t, only(t, cs, owner), c, "credential after another subject's assertion")
		})

		t.Run("ConcurrentRecordAssertion_OneWinner", func(t *testing.T) {
			cs, _ := h.NewStores(t)
			subject := h.NewSubject(t)
			c := newCred(t, subject, rpID, 1)
			insert(t, cs, c)
			const callers = 16
			var wg sync.WaitGroup
			var applied, refused, failed atomic.Int32
			start := make(chan struct{})
			for i := range callers {
				u := update(c)
				u.SignCount = c.SignCount + 1 + uint32(i) // each caller verified a different assertion
				wg.Go(func() {
					<-start
					switch ok, err := cs.RecordAssertion(ctx, u); {
					case err != nil:
						failed.Add(1)
					case ok:
						applied.Add(1)
					default:
						refused.Add(1)
					}
				})
			}
			close(start)
			wg.Wait()
			if applied.Load() != 1 || refused.Load() != callers-1 || failed.Load() != 0 {
				t.Fatalf("%d concurrent assertions: %d applied, %d refused, %d errors; want exactly 1, %d, 0 (the update must be conditional on the counter)",
					callers, applied.Load(), refused.Load(), failed.Load(), callers-1)
			}
		})

		t.Run("MarkCloneSuspected_Visible", func(t *testing.T) {
			cs, _ := h.NewStores(t)
			subject := h.NewSubject(t)
			c := newCred(t, subject, rpID, 1)
			insert(t, cs, c)
			if err := cs.MarkCloneSuspected(ctx, subject, c.ID, t1); err != nil {
				t.Fatalf("MarkCloneSuspected: %v", err)
			}
			want := c
			want.CloneSuspectedAt = t1
			assertSame(t, only(t, cs, subject), want, "credential after MarkCloneSuspected")
		})

		t.Run("Ensure_CreatesOnce", func(t *testing.T) {
			_, hs := h.NewStores(t)
			subject := h.NewSubject(t)
			first, second := bytes.Repeat([]byte{0x01}, 64), bytes.Repeat([]byte{0x02}, 64)
			got, err := hs.Ensure(ctx, subject, first)
			if err != nil || !bytes.Equal(got, first) {
				t.Fatalf("first Ensure = (%x, %v), want (%x, nil)", got, err, first)
			}
			got, err = hs.Ensure(ctx, subject, second)
			if err != nil || !bytes.Equal(got, first) {
				t.Fatalf("second Ensure = (%x, %v), want the first handle %x", got, err, first)
			}
			if _, err := hs.Subject(ctx, second); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("Subject of the discarded handle error = %v, want store.ErrNotFound", err)
			}
		})

		t.Run("ConcurrentEnsure_AllAgree", func(t *testing.T) {
			_, hs := h.NewStores(t)
			subject := h.NewSubject(t)
			const callers = 16
			var wg sync.WaitGroup
			results := make([][]byte, callers)
			errs := make([]error, callers)
			start := make(chan struct{})
			for i := range callers {
				wg.Go(func() {
					<-start
					results[i], errs[i] = hs.Ensure(ctx, subject, bytes.Repeat([]byte{byte(i + 1)}, 64))
				})
			}
			close(start)
			wg.Wait()
			for i := range callers {
				if errs[i] != nil {
					t.Fatalf("Ensure %d: %v", i, errs[i])
				}
				if !bytes.Equal(results[i], results[0]) {
					t.Fatalf("Ensure %d returned %x, Ensure 0 returned %x; concurrent callers must get one handle", i, results[i], results[0])
				}
			}
			if got, err := hs.Subject(ctx, results[0]); err != nil || got != subject {
				t.Fatalf("Subject(%x) = (%q, %v), want %q", results[0], got, err, subject)
			}
		})

		t.Run("SubjectByHandle", func(t *testing.T) {
			_, hs := h.NewStores(t)
			a, b := h.NewSubject(t), h.NewSubject(t)
			ha, hb := bytes.Repeat([]byte{0x0a}, 64), bytes.Repeat([]byte{0x0b}, 64)
			for _, e := range []struct {
				subject string
				handle  []byte
			}{{a, ha}, {b, hb}} {
				if _, err := hs.Ensure(ctx, e.subject, e.handle); err != nil {
					t.Fatalf("Ensure: %v", err)
				}
			}
			for _, e := range []struct {
				subject string
				handle  []byte
			}{{a, ha}, {b, hb}} {
				if got, err := hs.Subject(ctx, e.handle); err != nil || got != e.subject {
					t.Fatalf("Subject(%x) = (%q, %v), want %q", e.handle, got, err, e.subject)
				}
			}
		})

		t.Run("UnknownHandle_ErrNotFound", func(t *testing.T) {
			_, hs := h.NewStores(t)
			if _, err := hs.Subject(ctx, bytes.Repeat([]byte{0xee}, 64)); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("Subject of an unknown handle error = %v, want store.ErrNotFound", err)
			}
		})

		t.Run("CredentialRoundTripsEveryField", func(t *testing.T) {
			cs, _ := h.NewStores(t)
			subject := h.NewSubject(t)
			var want webauthn.Credential
			FillNonZero(t, &want)
			want.Subject, want.RPID = subject, rpID
			insert(t, cs, want)
			assertSame(t, only(t, cs, subject), want, "round trip")
		})
	}
}
