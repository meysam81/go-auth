package authtest

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"time"

	"github.com/meysam81/go-auth/v2/store"
	"github.com/meysam81/go-auth/v2/webauthn"
)

// memoryFlowStore is the in-memory [store.FlowStore]. For tests and examples,
// never production: it forgets everything on exit and shares nothing between
// processes.
type memoryFlowStore struct {
	now   func() time.Time
	flows map[string]store.Flow
	mu    sync.Mutex
}

// NewMemoryFlowStore returns an in-memory [store.FlowStore] for tests and
// examples, never production. now supplies the clock used for expiry; nil
// means [time.Now]. It copies flows on the way in and out, so a caller that
// edits a returned payload cannot change what is stored.
func NewMemoryFlowStore(now func() time.Time) store.FlowStore {
	if now == nil {
		now = time.Now
	}
	return &memoryFlowStore{now: now, flows: make(map[string]store.Flow)}
}

// Put stores f under id and returns [store.ErrDuplicate] when an unconsumed
// flow already holds the id.
func (m *memoryFlowStore) Put(_ context.Context, id string, f store.Flow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.flows[id]; ok {
		return store.ErrDuplicate
	}
	f.Payload = bytes.Clone(f.Payload)
	m.flows[id] = f
	return nil
}

// Take consumes the flow atomically. Missing, expired and already-consumed
// flows all return [store.ErrNotFound]; an expired entry is dropped.
func (m *memoryFlowStore) Take(_ context.Context, id string) (store.Flow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.flows[id]
	if !ok {
		return store.Flow{}, store.ErrNotFound
	}
	delete(m.flows, id)
	if !f.ExpiresAt.After(m.now()) {
		return store.Flow{}, store.ErrNotFound
	}
	return f, nil // the stored payload is gone from the map, so it is not shared
}

// MemoryWebAuthnStore is an in-memory [webauthn.CredentialStore] and
// [webauthn.HandleStore]. For tests and examples, never production. It
// deep-copies credentials on the way in and out.
type MemoryWebAuthnStore struct {
	handles   map[string][]byte // subject -> handle
	bySubject map[string]string // string(handle) -> subject
	creds     []webauthn.Credential
	mu        sync.Mutex
}

// NewMemoryWebAuthnStore returns an empty [MemoryWebAuthnStore].
func NewMemoryWebAuthnStore() *MemoryWebAuthnStore {
	return &MemoryWebAuthnStore{
		handles:   make(map[string][]byte),
		bySubject: make(map[string]string),
	}
}

func cloneCredential(c webauthn.Credential) webauthn.Credential {
	c.ID = bytes.Clone(c.ID)
	c.PublicKey = bytes.Clone(c.PublicKey)
	c.Transports = slices.Clone(c.Transports)
	if c.Discoverable != nil {
		d := *c.Discoverable
		c.Discoverable = &d
	}
	return c
}

// Insert stores c, refusing an ID any subject already holds.
func (m *MemoryWebAuthnStore) Insert(_ context.Context, c webauthn.Credential) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.creds {
		if bytes.Equal(m.creds[i].ID, c.ID) {
			return store.ErrDuplicate
		}
	}
	m.creds = append(m.creds, cloneCredential(c))
	return nil
}

// List returns the subject's credentials for rpID, in insertion order.
func (m *MemoryWebAuthnStore) List(_ context.Context, subject, rpID string) ([]webauthn.Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []webauthn.Credential
	for i := range m.creds {
		if m.creds[i].Subject == subject && m.creds[i].RPID == rpID {
			out = append(out, cloneCredential(m.creds[i]))
		}
	}
	return out, nil
}

// find returns the index of the subject's credential id, or -1. The caller
// holds the lock.
func (m *MemoryWebAuthnStore) find(subject string, id []byte) int {
	return slices.IndexFunc(m.creds, func(c webauthn.Credential) bool {
		return c.Subject == subject && bytes.Equal(c.ID, id)
	})
}

// RecordAssertion applies u only while the stored counter still equals
// u.PrevSignCount.
func (m *MemoryWebAuthnStore) RecordAssertion(_ context.Context, u webauthn.AssertionUpdate) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	i := m.find(u.Subject, u.CredentialID)
	if i < 0 || m.creds[i].SignCount != u.PrevSignCount {
		return false, nil
	}
	c := &m.creds[i]
	c.SignCount = u.SignCount
	c.BackupEligible = u.BackupEligible
	c.BackupState = u.BackupState
	c.Version = u.Version
	c.LastUsedAt = u.At
	return true, nil
}

// MarkCloneSuspected sets CloneSuspectedAt on the credential.
func (m *MemoryWebAuthnStore) MarkCloneSuspected(_ context.Context, subject string, id []byte, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	i := m.find(subject, id)
	if i < 0 {
		return store.ErrNotFound
	}
	m.creds[i].CloneSuspectedAt = at
	return nil
}

// Ensure returns the subject's handle, storing h first when it has none.
func (m *MemoryWebAuthnStore) Ensure(_ context.Context, subject string, h []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if have, ok := m.handles[subject]; ok {
		return bytes.Clone(have), nil
	}
	if _, taken := m.bySubject[string(h)]; taken {
		return nil, store.ErrDuplicate
	}
	m.handles[subject] = bytes.Clone(h)
	m.bySubject[string(h)] = subject
	return bytes.Clone(h), nil
}

// Subject resolves a handle, or returns [store.ErrNotFound].
func (m *MemoryWebAuthnStore) Subject(_ context.Context, handle []byte) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.bySubject[string(handle)]
	if !ok {
		return "", store.ErrNotFound
	}
	return s, nil
}

// Delete removes a credential. It is a test helper standing in for the
// application's own delete query; it does nothing when the credential is absent.
func (m *MemoryWebAuthnStore) Delete(subject string, id []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if i := m.find(subject, id); i >= 0 {
		m.creds = slices.Delete(m.creds, i, i+1)
	}
}

var (
	_ webauthn.CredentialStore = (*MemoryWebAuthnStore)(nil)
	_ webauthn.HandleStore     = (*MemoryWebAuthnStore)(nil)
)
