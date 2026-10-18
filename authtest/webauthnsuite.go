package authtest

import (
	"bytes"
	"encoding/base64"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/meysam81/go-auth/v2/store"
	"github.com/meysam81/go-auth/v2/webauthn"
)

// WebAuthnHarness connects [WebAuthnStoreSuite] to an application's stores.
type WebAuthnHarness struct {
	// NewStores returns stores no other subtest has written to; the suite
	// calls it once per subtest. The Concurrent subtests prove a write atomic
	// only when their 16 callers reach the database on separate connections
	// at the same moment. With a database/sql pool, give each store pair a
	// pool that already holds 16 open connections, as newDB in
	// examples/sqlitestore does: otherwise each caller may open a fresh one,
	// the callers run one after another, and a read followed by a write can
	// pass.
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
		// Below the microsecond too, at an odd microsecond count, so a store
		// that keeps a coarser grain (2 µs, 10 µs) moves it.
		t0 := time.Date(2026, 1, 2, 3, 4, 5, 123_457_789, time.UTC)
		t1 := t0.Add(48 * time.Hour)

		// newCred is a credential with every field non-zero, then pinned to
		// the values the tests reason about. Its ID is random.
		newCred := func(t *testing.T, subject, rp string) webauthn.Credential {
			t.Helper()
			var c webauthn.Credential
			FillNonZero(t, &c)
			c.Subject, c.RPID = subject, rp
			c.ID = randBytes(t, 16)
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
		// byID lists the subject's credentials and returns the one with id.
		byID := func(t *testing.T, cs webauthn.CredentialStore, subject string, id []byte) webauthn.Credential {
			t.Helper()
			got := list(t, cs, subject)
			for i := range got {
				if bytes.Equal(got[i].ID, id) {
					return got[i]
				}
			}
			t.Fatalf("credential %.16x... (%d bytes) missing from List (%d listed)", id, len(id), len(got))
			return webauthn.Credential{}
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
		// withSibling inserts c and a second credential of the same subject and
		// RP ID whose counter is sibCount. A synced passkey's siblings often
		// share a counter of zero, so a write that forgets the credential_id
		// predicate hits them too.
		withSibling := func(t *testing.T, cs webauthn.CredentialStore, c webauthn.Credential, sibCount uint32) webauthn.Credential {
			t.Helper()
			sib := newCred(t, c.Subject, c.RPID)
			sib.SignCount = sibCount
			insert(t, cs, c)
			insert(t, cs, sib)
			return sib
		}

		t.Run("InsertThenList", func(t *testing.T) {
			cs, _ := h.NewStores(t)
			subject := h.NewSubject(t)
			a, b := newCred(t, subject, rpID), newCred(t, subject, rpID)
			insert(t, cs, a)
			insert(t, cs, b)
			if got := list(t, cs, subject); len(got) != 2 {
				t.Fatalf("List returned %d credentials, want 2", len(got))
			}
			assertSame(t, byID(t, cs, subject, a.ID), a, "first listed credential")
			assertSame(t, byID(t, cs, subject, b.ID), b, "second listed credential")
		})

		t.Run("DuplicateIDSameSubject_ErrDuplicate", func(t *testing.T) {
			cs, _ := h.NewStores(t)
			subject := h.NewSubject(t)
			c := newCred(t, subject, rpID)
			insert(t, cs, c)
			if err := cs.Insert(ctx, c); !errors.Is(err, store.ErrDuplicate) {
				t.Fatalf("second Insert error = %v, want store.ErrDuplicate", err)
			}
		})

		t.Run("DuplicateIDOtherSubject_ErrDuplicate", func(t *testing.T) {
			cs, _ := h.NewStores(t)
			owner, intruder := h.NewSubject(t), h.NewSubject(t)
			c := newCred(t, owner, rpID)
			insert(t, cs, c)
			// The same credential ID under another subject, on the same RP ID
			// and on a different one: the unique index is on the ID alone.
			for _, rp := range []string{rpID, "other.test"} {
				stolen := newCred(t, intruder, rp)
				stolen.ID = c.ID
				if err := cs.Insert(ctx, stolen); !errors.Is(err, store.ErrDuplicate) {
					t.Fatalf("Insert of an ID another subject holds (RP ID %q): error = %v, want store.ErrDuplicate (a unique index on the credential ID alone)", rp, err)
				}
			}
			if got := list(t, cs, intruder); len(got) != 0 {
				t.Fatalf("the refused credential was stored for the other subject: %+v", got)
			}
			assertSame(t, byID(t, cs, owner, c.ID), c, "the owner's credential")
		})

		t.Run("ConcurrentInsert_OneWinner", func(t *testing.T) {
			cs, _ := h.NewStores(t)
			const callers = 16
			// One credential ID, each caller under its own subject: a SELECT
			// then INSERT, or a unique index on (subject, ID), lets more than
			// one through.
			id := randBytes(t, 16)
			subjects := make([]string, callers)
			for i := range subjects {
				subjects[i] = h.NewSubject(t)
			}
			var wg sync.WaitGroup
			var won, duplicate, failed atomic.Int32
			start := make(chan struct{})
			for i := range callers {
				c := newCred(t, subjects[i], rpID)
				c.ID = id
				wg.Go(func() {
					<-start
					switch err := cs.Insert(ctx, c); {
					case err == nil:
						won.Add(1)
					case errors.Is(err, store.ErrDuplicate):
						duplicate.Add(1)
					default:
						failed.Add(1)
					}
				})
			}
			close(start)
			wg.Wait()
			if won.Load() != 1 || duplicate.Load() != callers-1 || failed.Load() != 0 {
				t.Fatalf("%d concurrent Inserts of one credential ID: %d stored, %d store.ErrDuplicate, %d other errors; want exactly 1, %d, 0 (a unique index on the credential ID alone)",
					callers, won.Load(), duplicate.Load(), failed.Load(), callers-1)
			}
			held := 0
			for _, subject := range subjects {
				held += len(list(t, cs, subject))
			}
			if held != 1 {
				t.Fatalf("%d subjects list the credential ID, want 1", held)
			}
		})

		t.Run("ListFiltersByRPID", func(t *testing.T) {
			cs, _ := h.NewStores(t)
			subject := h.NewSubject(t)
			here, there := newCred(t, subject, rpID), newCred(t, subject, "other.test")
			insert(t, cs, here)
			insert(t, cs, there)
			if got := list(t, cs, subject); len(got) != 1 {
				t.Fatalf("List returned %d credentials for the asked RP ID, want 1", len(got))
			}
			assertSame(t, byID(t, cs, subject, here.ID), here, "credential for the asked RP ID")
		})

		t.Run("ListOtherSubjectIsEmpty", func(t *testing.T) {
			cs, _ := h.NewStores(t)
			owner, other := h.NewSubject(t), h.NewSubject(t)
			insert(t, cs, newCred(t, owner, rpID))
			if got := list(t, cs, other); len(got) != 0 {
				t.Fatalf("List for a subject with no credentials returned %+v", got)
			}
		})

		t.Run("RecordAssertion_Applies", func(t *testing.T) {
			cs, _ := h.NewStores(t)
			subject := h.NewSubject(t)
			c := newCred(t, subject, rpID)
			c.SignCount = 0
			sib := withSibling(t, cs, c, 0)

			// First assertion: backup eligible, not yet backed up. Comparing the
			// whole credential also proves nothing else moved.
			u := update(c)
			u.BackupEligible, u.BackupState = true, false
			applied, err := cs.RecordAssertion(ctx, u)
			if err != nil || !applied {
				t.Fatalf("RecordAssertion = (%v, %v), want (true, nil)", applied, err)
			}
			want := c
			want.SignCount, want.BackupEligible, want.BackupState = u.SignCount, true, false
			want.Version, want.LastUsedAt = u.Version, u.At
			assertSame(t, byID(t, cs, subject, c.ID), want, "credential after the first assertion")
			assertSame(t, byID(t, cs, subject, sib.ID), sib, "sibling credential after the first assertion")

			// Second assertion: the credential is now backed up too.
			u2 := update(want)
			u2.BackupEligible, u2.BackupState = true, true
			u2.At = t1.Add(time.Hour)
			applied, err = cs.RecordAssertion(ctx, u2)
			if err != nil || !applied {
				t.Fatalf("second RecordAssertion = (%v, %v), want (true, nil)", applied, err)
			}
			want.SignCount, want.BackupState, want.LastUsedAt = u2.SignCount, true, u2.At
			assertSame(t, byID(t, cs, subject, c.ID), want, "credential after the second assertion")
			assertSame(t, byID(t, cs, subject, sib.ID), sib, "sibling credential after the second assertion")
		})

		t.Run("RecordAssertion_StaleCounter_NotApplied", func(t *testing.T) {
			cs, _ := h.NewStores(t)
			subject := h.NewSubject(t)
			c := newCred(t, subject, rpID)
			c.SignCount = 0
			// The sibling's counter equals the stale PrevSignCount below, so a
			// write that ignores the credential ID would update it.
			sib := withSibling(t, cs, c, 1)
			u := update(c)
			u.PrevSignCount = 1 // the counter moved since the library read it
			applied, err := cs.RecordAssertion(ctx, u)
			if err != nil || applied {
				t.Fatalf("RecordAssertion with a stale counter = (%v, %v), want (false, nil)", applied, err)
			}
			assertSame(t, byID(t, cs, subject, c.ID), c, "credential after a stale assertion")
			assertSame(t, byID(t, cs, subject, sib.ID), sib, "sibling credential after a stale assertion")
		})

		t.Run("RecordAssertion_WrongSubject_NotApplied", func(t *testing.T) {
			cs, _ := h.NewStores(t)
			owner, other := h.NewSubject(t), h.NewSubject(t)
			c := newCred(t, owner, rpID)
			insert(t, cs, c)
			u := update(c)
			u.Subject = other // right credential ID, wrong subject
			applied, err := cs.RecordAssertion(ctx, u)
			if err != nil || applied {
				t.Fatalf("RecordAssertion for another subject = (%v, %v), want (false, nil)", applied, err)
			}
			assertSame(t, byID(t, cs, owner, c.ID), c, "credential after another subject's assertion")
		})

		t.Run("ConcurrentRecordAssertion_OneWinner", func(t *testing.T) {
			cs, _ := h.NewStores(t)
			subject := h.NewSubject(t)
			c := newCred(t, subject, rpID)
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

		// A counter that stays 0 and a last-used time equal to the stored one
		// leave the row unchanged: it still matches, so the update applies. A
		// driver that counts changed rows rather than matched ones (MySQL
		// without clientFoundRows) reports it as lost to a concurrent assertion.
		t.Run("RecordAssertion_UnchangedRow_Applies", func(t *testing.T) {
			cs, _ := h.NewStores(t)
			subject := h.NewSubject(t)
			c := asRegistered(t, subject, rpID)
			insert(t, cs, c)
			u := webauthn.AssertionUpdate{
				Subject: subject, CredentialID: c.ID, Version: webauthn.CurrentVersion, At: t1,
			}
			for _, attempt := range []string{"first", "identical second"} {
				applied, err := cs.RecordAssertion(ctx, u)
				if err != nil || !applied {
					t.Fatalf("%s RecordAssertion = (%v, %v), want (true, nil): a matched row applies whether or not a value changed", attempt, applied, err)
				}
			}
			want := c
			want.LastUsedAt = t1
			assertSame(t, byID(t, cs, subject, c.ID), want, "credential after two identical assertions")
		})

		t.Run("MarkCloneSuspected_Visible", func(t *testing.T) {
			cs, _ := h.NewStores(t)
			subject := h.NewSubject(t)
			c := newCred(t, subject, rpID)
			c.SignCount = 0
			sib := withSibling(t, cs, c, 0)
			if err := cs.MarkCloneSuspected(ctx, subject, c.ID, t1); err != nil {
				t.Fatalf("MarkCloneSuspected: %v", err)
			}
			want := c
			want.CloneSuspectedAt = t1
			assertSame(t, byID(t, cs, subject, c.ID), want, "credential after MarkCloneSuspected")
			assertSame(t, byID(t, cs, subject, sib.ID), sib, "sibling credential after MarkCloneSuspected")
		})

		// The library reads store.ErrNotFound as a credential removed during the
		// ceremony: a store that answers nil for an unknown credential has it
		// report a clone of a credential that is gone, and one that counts
		// changed rows answers ErrNotFound to the second of two concurrent
		// regressions that mark the same instant, which then reports no clone.
		t.Run("MarkCloneSuspected_ErrNotFoundOnlyWhenUnknown", func(t *testing.T) {
			cs, _ := h.NewStores(t)
			subject := h.NewSubject(t)
			c := newCred(t, subject, rpID)
			insert(t, cs, c)
			if err := cs.MarkCloneSuspected(ctx, subject, randBytes(t, 16), t1); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("MarkCloneSuspected of an unknown credential ID: error = %v, want store.ErrNotFound", err)
			}
			for _, attempt := range []string{"first", "identical second"} {
				if err := cs.MarkCloneSuspected(ctx, subject, c.ID, t1); err != nil {
					t.Fatalf("%s MarkCloneSuspected = %v, want nil: a matched row is marked whether or not a value changed", attempt, err)
				}
			}
			want := c
			want.CloneSuspectedAt = t1
			assertSame(t, byID(t, cs, subject, c.ID), want, "credential after two identical marks")
		})

		// FinishRegistration returns store.ErrDuplicate to the application as
		// "this credential ID is already registered". A store that maps every
		// constraint violation to it reports a CHECK or a NOT NULL as that. Each
		// credential below, under a fresh ID, is one the library never writes:
		// a store may accept it, but a refusal must not be store.ErrDuplicate.
		// The application's own unique indexes fall under the same rule; the
		// suite cannot see them.
		t.Run("Insert_OtherRefusal_NotErrDuplicate", func(t *testing.T) {
			cs, _ := h.NewStores(t)
			for _, tc := range []struct {
				name string
				edit func(c *webauthn.Credential)
			}{
				{"a 1024-byte credential ID", func(c *webauthn.Credential) { c.ID = randBytes(t, 1024) }},
				{"an empty public key", func(c *webauthn.Credential) { c.PublicKey = nil }},
				{"an empty RP ID", func(c *webauthn.Credential) { c.RPID = "" }},
				{"a zero creation time", func(c *webauthn.Credential) { c.CreatedAt = time.Time{} }},
				{"a version above CurrentVersion", func(c *webauthn.Credential) { c.Version = math.MaxUint16 }},
			} {
				c := newCred(t, h.NewSubject(t), rpID)
				tc.edit(&c)
				if err := cs.Insert(ctx, c); errors.Is(err, store.ErrDuplicate) {
					t.Errorf("Insert of a credential with %s under a fresh ID: error = %v; store.ErrDuplicate means the credential ID is held, and only that", tc.name, err)
				}
			}
		})

		t.Run("Ensure_CreatesOnce", func(t *testing.T) {
			_, hs := h.NewStores(t)
			subject := h.NewSubject(t)
			first, second := randBytes(t, 64), randBytes(t, 64)
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
				proposed := randBytes(t, 64)
				wg.Go(func() {
					<-start
					results[i], errs[i] = hs.Ensure(ctx, subject, proposed)
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
			ha, hb := randBytes(t, 64), randBytes(t, 64)
			// Each Ensure returns the handle it stored, not another subject's.
			for _, e := range []struct {
				subject string
				handle  []byte
			}{{a, ha}, {b, hb}} {
				got, err := hs.Ensure(ctx, e.subject, e.handle)
				if err != nil || !bytes.Equal(got, e.handle) {
					t.Fatalf("Ensure(%q) = (%x, %v), want (%x, nil)", e.subject, got, err, e.handle)
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
			// Handles match exactly: a prefix and an extension are other handles.
			for name, near := range map[string][]byte{
				"a prefix":    ha[:len(ha)-1],
				"an extended": append(bytes.Clone(ha), 0),
			} {
				if got, err := hs.Subject(ctx, near); !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("Subject(%s handle) = (%q, %v), want store.ErrNotFound", name, got, err)
				}
			}
		})

		// A handle resolves to one subject. An Ensure that replaces on conflict
		// moves the handle, and its owner's passkeys then resolve to the other
		// subject.
		t.Run("EnsureHandleOfAnotherSubject_Refused", func(t *testing.T) {
			_, hs := h.NewStores(t)
			owner, other := h.NewSubject(t), h.NewSubject(t)
			held := randBytes(t, 64)
			if got, err := hs.Ensure(ctx, owner, held); err != nil || !bytes.Equal(got, held) {
				t.Fatalf("Ensure(owner) = (%x, %v), want (%x, nil)", got, err, held)
			}
			if got, err := hs.Ensure(ctx, other, held); err == nil {
				t.Fatalf("Ensure of the owner's handle for a subject with none = (%x, nil), want an error", got)
			}
			if got, err := hs.Subject(ctx, held); err != nil || got != owner {
				t.Fatalf("Subject of the owner's handle after the refused Ensure = (%q, %v), want %q", got, err, owner)
			}
			fresh := randBytes(t, 64)
			if got, err := hs.Ensure(ctx, other, fresh); err != nil || !bytes.Equal(got, fresh) {
				t.Fatalf("Ensure(other) after the refusal = (%x, %v), want its own fresh handle %x: the refusal stored nothing", got, err, fresh)
			}
		})

		// Handles are bytes. Kept as text under a case-insensitive collation,
		// raw or base64-encoded, a handle matches others that differ only in
		// the case of a letter. Both handles here are 64 bytes, the length the
		// library creates.
		t.Run("SubjectByHandle_CaseVariant_ErrNotFound", func(t *testing.T) {
			_, hs := h.NewStores(t)
			raw := randLetters(t, 64)
			// 64 bytes encode to 86 base64 characters and "==". The 86th carries
			// the last byte's two low bits and four zero bits, so it is one of A,
			// Q, g and w, and the variant keeps it.
			text := append(randLetters(t, 85), "AQgw"[randBytes(t, 1)[0]%4], '=', '=')
			variant := append(swapCase(text[:85]), text[85:]...)
			b64, err := base64.StdEncoding.Strict().DecodeString(string(text))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			b64Variant, err := base64.StdEncoding.Strict().DecodeString(string(variant))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			for _, tc := range []struct {
				form            string
				handle, variant []byte
			}{
				{"raw", raw, swapCase(raw)},
				{"base64-encoded", b64, b64Variant},
			} {
				subject := h.NewSubject(t)
				if got, err := hs.Ensure(ctx, subject, tc.handle); err != nil || !bytes.Equal(got, tc.handle) {
					t.Fatalf("Ensure(%s) = (%x, %v), want (%x, nil)", tc.form, got, err, tc.handle)
				}
				if got, err := hs.Subject(ctx, tc.variant); !errors.Is(err, store.ErrNotFound) {
					t.Errorf("Subject of a handle whose %s form differs only in letter case = (%q, %v), want store.ErrNotFound (compare bytes exactly)", tc.form, got, err)
				}
			}
		})

		t.Run("UnknownHandle_ErrNotFound", func(t *testing.T) {
			_, hs := h.NewStores(t)
			if _, err := hs.Subject(ctx, randBytes(t, 64)); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("Subject of an unknown handle error = %v, want store.ErrNotFound", err)
			}
		})

		// roundTrip inserts a fully populated credential, shaped by shape, and
		// expects List to return it unchanged.
		roundTrip := func(t *testing.T, shape func(c *webauthn.Credential)) {
			t.Helper()
			cs, _ := h.NewStores(t)
			subject := h.NewSubject(t)
			var want webauthn.Credential
			FillNonZero(t, &want)
			want.Subject, want.RPID = subject, rpID
			want.ID = randBytes(t, 16)
			shape(&want)
			insert(t, cs, want)
			assertSame(t, byID(t, cs, subject, want.ID), want, "round trip")
		}

		t.Run("CredentialRoundTripsEveryField", func(t *testing.T) {
			roundTrip(t, func(c *webauthn.Credential) {
				c.SignCount = math.MaxUint32 // the top of an unsigned 32-bit counter
				c.Algorithm = -257           // a negative COSE algorithm
				// Instants in zones on both sides of UTC: a store that keeps the
				// wall clock and drops the offset moves them.
				c.CreatedAt = c.CreatedAt.In(time.FixedZone("+14", 14*3600))
				c.LastUsedAt = c.LastUsedAt.In(time.FixedZone("-12", -12*3600))
				// On an exact microsecond: a store may drop what lies below it in
				// either direction, but one that shifts every time by a microsecond
				// moves this one by a whole one.
				c.CloneSuspectedAt = c.CloneSuspectedAt.Truncate(time.Microsecond).In(time.FixedZone("+5:45", 5*3600+45*60))
			})
		})

		t.Run("CredentialRoundTrips_InvertedFlags", func(t *testing.T) {
			roundTrip(t, func(c *webauthn.Credential) {
				no := false
				c.BackupEligible, c.BackupState, c.UVInitialized = true, false, false
				c.Discoverable = &no
			})
		})

		t.Run("CredentialRoundTrips_BackedUpNotUVInitialized", func(t *testing.T) {
			roundTrip(t, func(c *webauthn.Credential) {
				c.BackupEligible, c.BackupState, c.UVInitialized = false, true, true
			})
		})

		t.Run("CredentialRoundTrips_DiscoverableUnknown", func(t *testing.T) {
			roundTrip(t, func(c *webauthn.Credential) { c.Discoverable = nil })
		})

		// FinishRegistration stores a credential never used, often with no
		// transports, AAGUID or credProps reported: a NOT NULL last-used column,
		// or nil transports written as JSON null, refuses real registrations.
		t.Run("CredentialRoundTrips_AsRegistered", func(t *testing.T) {
			cs, _ := h.NewStores(t)
			subject := h.NewSubject(t)
			c := asRegistered(t, subject, rpID)
			insert(t, cs, c)
			assertSame(t, byID(t, cs, subject, c.ID), c, "credential as FinishRegistration stores it")
		})

		t.Run("CredentialRoundTrips_LargestValues", func(t *testing.T) {
			roundTrip(t, func(c *webauthn.Credential) {
				c.ID = randBytes(t, 1023) // WebAuthn's longest credential ID
				// Past any key the configured algorithms produce (an RSA-4096
				// COSE key is about 550 bytes): a fixed-width column truncates.
				c.PublicKey = randBytes(t, 2048)
			})
		})
	}
}

// randLetters returns n ASCII letters drawn from crypto/rand, so a harness
// whose stores share one database still sees unique handles.
func randLetters(t *testing.T, n int) []byte {
	t.Helper()
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := randBytes(t, n)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return b
}

// swapCase returns b with the case of every letter swapped; b holds ASCII
// letters only, as randLetters returns.
func swapCase(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = c ^ 0x20 // 'a' ^ 0x20 == 'A'
	}
	return out
}

// asRegistered is a credential as FinishRegistration may store it: every
// field the library can leave unset is zero (no transports, AAGUID or
// credProps reported, a zero counter, never used, no backup flags).
func asRegistered(t *testing.T, subject, rpID string) webauthn.Credential {
	t.Helper()
	return webauthn.Credential{
		Version:   webauthn.CurrentVersion,
		ID:        randBytes(t, 16),
		Subject:   subject,
		RPID:      rpID,
		PublicKey: randBytes(t, 77),
		Algorithm: -7,
		CreatedAt: time.Date(2026, 1, 2, 3, 4, 5, 987_653_321, time.UTC),
	}
}
