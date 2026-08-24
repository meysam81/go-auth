package oidc

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/meysam81/go-auth/storage"
	"golang.org/x/oauth2"
)

// The tests in this file are named for the attack each hardening step denies,
// per the test program in docs/security-hardening.md section 6. Every one of
// them must fail if the corresponding fix is reverted.

// --- fakes -----------------------------------------------------------------

type fakeStateStore struct {
	mu       sync.Mutex
	states   map[string]*storage.OIDCState
	ttls     map[string]time.Duration
	storeErr error
	getErr   error
}

func newFakeStateStore() *fakeStateStore {
	return &fakeStateStore{
		states: make(map[string]*storage.OIDCState),
		ttls:   make(map[string]time.Duration),
	}
}

func (s *fakeStateStore) StoreState(_ context.Context, state string, data *storage.OIDCState, ttl time.Duration) error {
	if s.storeErr != nil {
		return s.storeErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[state] = data
	s.ttls[state] = ttl
	return nil
}

func (s *fakeStateStore) GetState(_ context.Context, state string) (*storage.OIDCState, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.states[state]
	if !ok {
		return nil, storage.ErrNotFound
	}
	delete(s.states, state) // one-time use, as the interface documents
	return data, nil
}

func (s *fakeStateStore) DeleteState(_ context.Context, state string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.states, state)
	return nil
}

// peek returns the stored record without consuming it.
func (s *fakeStateStore) peek(state string) *storage.OIDCState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.states[state]
}

type fakeUserStore struct {
	mu      sync.Mutex
	byEmail map[string]*storage.User
	created []*storage.User
}

func newFakeUserStore(existing ...*storage.User) *fakeUserStore {
	s := &fakeUserStore{byEmail: make(map[string]*storage.User)}
	for _, u := range existing {
		s.byEmail[u.Email] = u
	}
	return s
}

func (s *fakeUserStore) CreateUser(_ context.Context, user *storage.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byEmail[user.Email]; ok {
		return storage.ErrAlreadyExists
	}
	s.byEmail[user.Email] = user
	s.created = append(s.created, user)
	return nil
}

func (s *fakeUserStore) GetUserByID(_ context.Context, id string) (*storage.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.byEmail {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (s *fakeUserStore) GetUserByEmail(_ context.Context, email string) (*storage.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byEmail[email]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return u, nil
}

func (s *fakeUserStore) GetUserByUsername(_ context.Context, username string) (*storage.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.byEmail {
		if u.Username == username {
			return u, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (s *fakeUserStore) UpdateUser(_ context.Context, user *storage.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byEmail[user.Email] = user
	return nil
}

func (s *fakeUserStore) DeleteUser(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for email, u := range s.byEmail {
		if u.ID == id {
			delete(s.byEmail, email)
			return nil
		}
	}
	return storage.ErrNotFound
}

func (s *fakeUserStore) createdCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.created)
}

type fakeProvider struct {
	name         string
	cfg          *oauth2.Config
	oidcProvider *oidc.Provider
	info         *UserInfo
	extractErr   error
}

func (p *fakeProvider) Name() string                    { return p.name }
func (p *fakeProvider) GetOAuth2Config() *oauth2.Config { return p.cfg }
func (p *fakeProvider) GetOIDCProvider() *oidc.Provider { return p.oidcProvider }

func (p *fakeProvider) ExtractUserInfo(_ context.Context, _ *oauth2.Token) (*UserInfo, error) {
	if p.extractErr != nil {
		return nil, p.extractErr
	}
	clone := *p.info
	return &clone, nil
}

type tokenServer struct {
	*httptest.Server
	mu   sync.Mutex
	form url.Values
}

func (ts *tokenServer) lastForm() url.Values {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.form
}

func newTokenServer(t *testing.T) *tokenServer {
	t.Helper()
	ts := &tokenServer{}
	ts.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// gosec G120: bound the request body before parsing it, even in a test
		// fixture — an unbounded ParseForm is a memory-exhaustion primitive.
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := r.ParseForm(); err != nil {
			t.Errorf("token endpoint: parse form: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ts.mu.Lock()
		ts.form = r.Form
		ts.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, `{"access_token":"at","token_type":"Bearer","id_token":"idt"}`); err != nil {
			t.Errorf("token endpoint: write response: %v", err)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

// --- harness ---------------------------------------------------------------

type harness struct {
	client   *Client
	states   *fakeStateStore
	users    *fakeUserStore
	provider *fakeProvider
	tokens   *tokenServer
}

type harnessOptions struct {
	oauth2Only bool
	users      *fakeUserStore
	noUsers    bool
	linkPolicy LinkPolicy
	allowlist  []string
	httpClient *http.Client
	info       *UserInfo
}

func newHarness(t *testing.T, opts harnessOptions) *harness {
	t.Helper()

	tokens := newTokenServer(t)

	info := opts.info
	if info == nil {
		info = &UserInfo{
			Subject:       "sub-1",
			Email:         "user@example.com",
			EmailVerified: true,
			Name:          "Example User",
			RawClaims: map[string]interface{}{
				"sub":    "sub-1",
				"email":  "user@example.com",
				"groups": []interface{}{"admins"},
			},
		}
	}

	provider := &fakeProvider{
		name: "acme",
		cfg: &oauth2.Config{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			RedirectURL:  "https://app.example/callback",
			Scopes:       []string{"openid", "email"},
			Endpoint: oauth2.Endpoint{
				AuthURL:   "https://idp.example/authorize",
				TokenURL:  tokens.URL,
				AuthStyle: oauth2.AuthStyleInParams,
			},
		},
		info: info,
	}
	if !opts.oauth2Only {
		provider.oidcProvider = (&oidc.ProviderConfig{
			IssuerURL: "https://idp.example",
			AuthURL:   "https://idp.example/authorize",
			TokenURL:  tokens.URL,
			JWKSURL:   "https://idp.example/jwks",
		}).NewProvider(context.Background())
	}

	users := opts.users
	if users == nil && !opts.noUsers {
		users = newFakeUserStore()
	}

	states := newFakeStateStore()
	cfg := Config{
		Providers:      []Provider{provider},
		StateStore:     states,
		RedirectURL:    "https://app.example/home",
		LinkPolicy:     opts.linkPolicy,
		ClaimAllowlist: opts.allowlist,
		HTTPClient:     opts.httpClient,
	}
	if users != nil {
		cfg.UserStore = users
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	return &harness{client: client, states: states, users: users, provider: provider, tokens: tokens}
}

// start begins a bound flow and returns the parsed authorization URL query,
// the state, the binding value and the stored state record.
func (h *harness) start(t *testing.T) (url.Values, string, string, *storage.OIDCState) {
	t.Helper()
	req, err := h.client.GetAuthorizationURLWithBinding(context.Background(), AuthURLOptions{Provider: "acme"})
	if err != nil {
		t.Fatalf("GetAuthorizationURLWithBinding: %v", err)
	}
	parsed, err := url.Parse(req.URL)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}
	stored := h.states.peek(req.State)
	if stored == nil {
		t.Fatalf("state %q was not stored", req.State)
	}
	// An OIDC flow demands the nonce back in the ID token; mirror what a
	// well-behaved provider returns.
	if stored.Nonce != "" && h.provider.info.RawClaims != nil {
		h.provider.info.RawClaims["nonce"] = stored.Nonce
	}
	return parsed.Query(), req.State, req.Binding, stored
}

// --- F-17: PKCE ------------------------------------------------------------

func TestAuthorizationURLCarriesS256PKCEChallenge(t *testing.T) {
	t.Parallel()
	h := newHarness(t, harnessOptions{})

	query, _, _, stored := h.start(t)

	if got := query.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, want S256 (F-17, RFC 9700 2.1.1)", got)
	}
	challenge := query.Get("code_challenge")
	if challenge == "" {
		t.Fatal("authorization URL carries no code_challenge (F-17)")
	}

	verifier, err := metadataString(stored.Metadata, StateMetadataKeyPKCEVerifier)
	if err != nil {
		t.Fatalf("read verifier: %v", err)
	}
	if verifier == "" {
		t.Fatal("no PKCE verifier stored with the state (F-17)")
	}
	if challenge == verifier {
		t.Error("the plain verifier was sent as the challenge; S256 was not applied (F-17)")
	}
	if want := oauth2.S256ChallengeFromVerifier(verifier); challenge != want {
		t.Errorf("code_challenge = %q, want the S256 hash of the stored verifier", challenge)
	}
}

func TestExchangePresentsPKCEVerifier(t *testing.T) {
	t.Parallel()
	h := newHarness(t, harnessOptions{})

	_, state, binding, stored := h.start(t)
	verifier, err := metadataString(stored.Metadata, StateMetadataKeyPKCEVerifier)
	if err != nil {
		t.Fatalf("read verifier: %v", err)
	}

	if _, err := h.client.HandleCallbackWithBinding(context.Background(), state, "code", binding); err != nil {
		t.Fatalf("HandleCallbackWithBinding: %v", err)
	}

	if got := h.tokens.lastForm().Get("code_verifier"); got != verifier {
		t.Errorf("token request code_verifier = %q, want the stored verifier (F-17)", got)
	}
}

// --- F-18: nonce -----------------------------------------------------------

func TestAuthorizationURLCarriesNonceForOIDCProvider(t *testing.T) {
	t.Parallel()
	h := newHarness(t, harnessOptions{})

	query, _, _, stored := h.start(t)

	if stored.Nonce == "" {
		t.Fatal("no nonce recorded in the state (F-18)")
	}
	if got := query.Get("nonce"); got != stored.Nonce {
		t.Errorf("authorization URL nonce = %q, want %q (F-18)", got, stored.Nonce)
	}
}

func TestAuthorizationURLOmitsNonceForOAuth2OnlyProvider(t *testing.T) {
	t.Parallel()
	h := newHarness(t, harnessOptions{oauth2Only: true})

	query, _, _, stored := h.start(t)

	if stored.Nonce != "" {
		t.Errorf("nonce requested from an OAuth2-only provider that cannot echo it: %q", stored.Nonce)
	}
	if got := query.Get("nonce"); got != "" {
		t.Errorf("authorization URL nonce = %q, want none", got)
	}
}

func TestCallbackRejectsIDTokenWithoutNonceClaim(t *testing.T) {
	t.Parallel()
	h := newHarness(t, harnessOptions{})

	_, state, binding, _ := h.start(t)
	delete(h.provider.info.RawClaims, "nonce") // a token minted without the nonce we asked for

	_, err := h.client.HandleCallbackWithBinding(context.Background(), state, "code", binding)
	if !errors.Is(err, ErrMissingNonce) {
		t.Fatalf("error = %v, want ErrMissingNonce (F-18)", err)
	}
}

func TestCallbackRejectsReplayedNonce(t *testing.T) {
	t.Parallel()
	h := newHarness(t, harnessOptions{})

	_, state, binding, _ := h.start(t)
	// A token captured from a different authentication carries that flow's nonce.
	h.provider.info.RawClaims["nonce"] = "nonce-from-another-flow"

	_, err := h.client.HandleCallbackWithBinding(context.Background(), state, "code", binding)
	if !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("error = %v, want ErrNonceMismatch (F-18)", err)
	}
}

// --- F-16: browser binding -------------------------------------------------

func TestBindingIsStoredOnlyAsADigest(t *testing.T) {
	t.Parallel()
	h := newHarness(t, harnessOptions{})

	_, _, binding, stored := h.start(t)

	if binding == "" {
		t.Fatal("no binding value returned to the caller (F-16)")
	}
	recorded, err := metadataString(stored.Metadata, StateMetadataKeyBinding)
	if err != nil {
		t.Fatalf("read binding: %v", err)
	}
	if recorded == binding {
		t.Error("the binding value is stored verbatim; a reader of the state store can replay it (F-16)")
	}
	if recorded != digest(binding) {
		t.Errorf("stored binding = %q, want the SHA-256 digest of the issued value", recorded)
	}
}

func TestCallbackRejectsLoginCSRFWithoutBinding(t *testing.T) {
	t.Parallel()
	h := newHarness(t, harnessOptions{})

	_, state, _, _ := h.start(t)

	// The victim's browser holds no binding cookie: this is the attacker's
	// callback URL pasted into someone else's session.
	_, err := h.client.HandleCallback(context.Background(), state, "code")
	if !errors.Is(err, ErrMissingBinding) {
		t.Fatalf("error = %v, want ErrMissingBinding (F-16, CWE-352)", err)
	}
}

func TestCallbackRejectsWrongBinding(t *testing.T) {
	t.Parallel()
	h := newHarness(t, harnessOptions{})

	_, state, binding, _ := h.start(t)

	_, err := h.client.HandleCallbackWithBinding(context.Background(), state, "code", binding+"x")
	if !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("error = %v, want ErrBindingMismatch (F-16)", err)
	}
}

func TestCallbackAcceptsCorrectBinding(t *testing.T) {
	t.Parallel()
	h := newHarness(t, harnessOptions{})

	_, state, binding, _ := h.start(t)

	result, err := h.client.HandleCallbackWithBinding(context.Background(), state, "code", binding)
	if err != nil {
		t.Fatalf("HandleCallbackWithBinding: %v", err)
	}
	if result.UserInfo.Subject != "sub-1" {
		t.Errorf("subject = %q, want sub-1", result.UserInfo.Subject)
	}
	if result.RedirectURL != "https://app.example/home" {
		t.Errorf("redirect = %q, want the configured default", result.RedirectURL)
	}
}

func TestUnboundFlowStillWorksThroughTheOldEntryPoint(t *testing.T) {
	t.Parallel()
	h := newHarness(t, harnessOptions{})

	authURL, err := h.client.GetAuthorizationURL(context.Background(), AuthURLOptions{Provider: "acme"})
	if err != nil {
		t.Fatalf("GetAuthorizationURL: %v", err)
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	state := parsed.Query().Get("state")
	stored := h.states.peek(state)
	if stored == nil {
		t.Fatal("state not stored")
	}
	if _, ok := stored.Metadata[StateMetadataKeyBinding]; ok {
		t.Error("the unbound entry point issued a binding it cannot return to the caller")
	}
	h.provider.info.RawClaims["nonce"] = stored.Nonce

	if _, err := h.client.HandleCallback(context.Background(), state, "code"); err != nil {
		t.Fatalf("HandleCallback on an unbound flow: %v", err)
	}
}

func TestCallbackRejectsCorruptBindingRecord(t *testing.T) {
	t.Parallel()
	h := newHarness(t, harnessOptions{})

	_, state, binding, stored := h.start(t)
	stored.Metadata[StateMetadataKeyBinding] = 42 // rewritten by something that is not this package

	_, err := h.client.HandleCallbackWithBinding(context.Background(), state, "code", binding)
	if !errors.Is(err, ErrCorruptState) {
		t.Fatalf("error = %v, want ErrCorruptState", err)
	}
}

// --- F-01: identity --------------------------------------------------------

func TestCallbackRejectsAssertionWithoutSubject(t *testing.T) {
	t.Parallel()
	h := newHarness(t, harnessOptions{})

	_, state, binding, _ := h.start(t)
	h.provider.info.Subject = ""

	_, err := h.client.HandleCallbackWithBinding(context.Background(), state, "code", binding)
	if !errors.Is(err, ErrMissingSubject) {
		t.Fatalf("error = %v, want ErrMissingSubject (F-01, OIDC Core 2)", err)
	}
}

func TestClaimsOnlyCallbackStillRequiresSubject(t *testing.T) {
	t.Parallel()
	// With no user store there is no find-or-create path to fall back on, so
	// this pins the subject requirement in the callback itself: an assertion
	// with no sub names no identity at all (F-01, OIDC Core 2).
	h := newHarness(t, harnessOptions{noUsers: true})

	_, state, binding, _ := h.start(t)
	h.provider.info.Subject = ""

	_, err := h.client.HandleCallbackWithBinding(context.Background(), state, "code", binding)
	if !errors.Is(err, ErrMissingSubject) {
		t.Fatalf("error = %v, want ErrMissingSubject (F-01)", err)
	}
}

func TestFindOrCreateRefusesUnverifiedEmail(t *testing.T) {
	t.Parallel()
	users := newFakeUserStore(&storage.User{
		ID:       "victim",
		Email:    "victim@example.com",
		Provider: "acme",
		Metadata: map[string]interface{}{UserMetadataKeyProviderSubject: "sub-victim"},
	})
	h := newHarness(t, harnessOptions{users: users})

	_, state, binding, _ := h.start(t)
	// The nOAuth shape: an IdP asserting someone else's address, unverified.
	h.provider.info.Subject = "sub-attacker"
	h.provider.info.Email = "victim@example.com"
	h.provider.info.EmailVerified = false

	_, err := h.client.HandleCallbackWithBinding(context.Background(), state, "code", binding)
	if !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("error = %v, want ErrEmailNotVerified (F-01, CVE-2023-28131)", err)
	}
	if got := users.createdCount(); got != 0 {
		t.Errorf("created %d users on a refused assertion, want 0", got)
	}
}

func TestFindOrCreateRefusesCrossProviderAdoption(t *testing.T) {
	t.Parallel()
	users := newFakeUserStore(&storage.User{
		ID:       "victim",
		Email:    "user@example.com",
		Provider: "google",
		Metadata: map[string]interface{}{UserMetadataKeyProviderSubject: "sub-1"},
	})
	h := newHarness(t, harnessOptions{users: users})

	_, state, binding, _ := h.start(t)

	// Same email, same subject string, different provider: the account was not
	// created by the IdP now asserting it.
	_, err := h.client.HandleCallbackWithBinding(context.Background(), state, "code", binding)
	if !errors.Is(err, ErrAccountLinkRequired) {
		t.Fatalf("error = %v, want ErrAccountLinkRequired (F-01)", err)
	}
}

func TestFindOrCreateRefusesSubjectMismatch(t *testing.T) {
	t.Parallel()
	users := newFakeUserStore(&storage.User{
		ID:       "victim",
		Email:    "user@example.com",
		Provider: "acme",
		Metadata: map[string]interface{}{UserMetadataKeyProviderSubject: "sub-victim"},
	})
	h := newHarness(t, harnessOptions{users: users})

	_, state, binding, _ := h.start(t)

	// Same provider, verified email, but a different sub: a tenant admin
	// re-pointing an address at a new account.
	_, err := h.client.HandleCallbackWithBinding(context.Background(), state, "code", binding)
	if !errors.Is(err, ErrAccountLinkRequired) {
		t.Fatalf("error = %v, want ErrAccountLinkRequired (F-01)", err)
	}
}

func TestFindOrCreateRefusesAccountWithNoRecordedSubject(t *testing.T) {
	t.Parallel()
	users := newFakeUserStore(&storage.User{
		ID:       "legacy",
		Email:    "user@example.com",
		Provider: "acme",
	})
	h := newHarness(t, harnessOptions{users: users})

	_, state, binding, _ := h.start(t)

	_, err := h.client.HandleCallbackWithBinding(context.Background(), state, "code", binding)
	if !errors.Is(err, ErrAccountLinkRequired) {
		t.Fatalf("error = %v, want ErrAccountLinkRequired for an account with no recorded subject (F-01)", err)
	}
}

func TestFindOrCreateAdoptsSameProviderAndSubject(t *testing.T) {
	t.Parallel()
	existing := &storage.User{
		ID:       "returning",
		Email:    "user@example.com",
		Provider: "acme",
		Metadata: map[string]interface{}{UserMetadataKeyProviderSubject: "sub-1"},
	}
	h := newHarness(t, harnessOptions{users: newFakeUserStore(existing)})

	_, state, binding, _ := h.start(t)

	result, err := h.client.HandleCallbackWithBinding(context.Background(), state, "code", binding)
	if err != nil {
		t.Fatalf("HandleCallbackWithBinding: %v", err)
	}
	if result.User == nil || result.User.ID != "returning" {
		t.Fatalf("user = %+v, want the existing account", result.User)
	}
	if result.IsNewUser {
		t.Error("IsNewUser = true for an existing account")
	}
}

func TestLinkPolicyCanAuthorizeARefusedLink(t *testing.T) {
	t.Parallel()
	existing := &storage.User{
		ID:       "victim",
		Email:    "user@example.com",
		Provider: "google",
		Metadata: map[string]interface{}{UserMetadataKeyProviderSubject: "sub-other"},
	}
	var seen *storage.User
	h := newHarness(t, harnessOptions{
		users: newFakeUserStore(existing),
		linkPolicy: func(_ context.Context, u *storage.User, info *UserInfo) (bool, error) {
			seen = u
			return info.Subject == "sub-1", nil
		},
	})

	_, state, binding, _ := h.start(t)

	result, err := h.client.HandleCallbackWithBinding(context.Background(), state, "code", binding)
	if err != nil {
		t.Fatalf("HandleCallbackWithBinding: %v", err)
	}
	if seen == nil || seen.ID != "victim" {
		t.Error("LinkPolicy was not consulted with the existing account")
	}
	if result.User == nil || result.User.ID != "victim" {
		t.Fatalf("user = %+v, want the linked account", result.User)
	}
}

func TestLinkPolicyErrorAbortsTheCallback(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("directory unavailable")
	existing := &storage.User{
		ID:       "victim",
		Email:    "user@example.com",
		Provider: "google",
		Metadata: map[string]interface{}{UserMetadataKeyProviderSubject: "sub-other"},
	}
	h := newHarness(t, harnessOptions{
		users: newFakeUserStore(existing),
		linkPolicy: func(context.Context, *storage.User, *UserInfo) (bool, error) {
			return false, sentinel
		},
	})

	_, state, binding, _ := h.start(t)

	_, err := h.client.HandleCallbackWithBinding(context.Background(), state, "code", binding)
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want the policy's own error", err)
	}
}

func TestCallbackWithoutUserStoreReturnsClaimsOnly(t *testing.T) {
	t.Parallel()
	h := newHarness(t, harnessOptions{noUsers: true})

	_, state, binding, _ := h.start(t)

	result, err := h.client.HandleCallbackWithBinding(context.Background(), state, "code", binding)
	if err != nil {
		t.Fatalf("HandleCallbackWithBinding: %v", err)
	}
	if result.User != nil {
		t.Errorf("user = %+v, want nil when no user store is configured", result.User)
	}
	if result.UserInfo.Provider != "acme" {
		t.Errorf("provider = %q, want the provider that started the flow", result.UserInfo.Provider)
	}
}

// --- F-21: claim leakage ---------------------------------------------------

func TestCreatedUserStoresOnlyTheProviderSubject(t *testing.T) {
	t.Parallel()
	users := newFakeUserStore()
	h := newHarness(t, harnessOptions{users: users})

	_, state, binding, _ := h.start(t)

	result, err := h.client.HandleCallbackWithBinding(context.Background(), state, "code", binding)
	if err != nil {
		t.Fatalf("HandleCallbackWithBinding: %v", err)
	}
	if !result.IsNewUser {
		t.Fatal("IsNewUser = false, want a newly created account")
	}
	if _, leaked := result.User.Metadata["raw_claims"]; leaked {
		t.Error("the whole raw claim set was copied into user metadata (F-21, CWE-200)")
	}
	if _, leaked := result.User.Metadata["groups"]; leaked {
		t.Error("a claim outside the allow-list reached user metadata (F-21)")
	}
	if len(result.User.Metadata) != 1 {
		t.Errorf("metadata = %v, want only the provider subject", result.User.Metadata)
	}
	if result.User.Metadata[UserMetadataKeyProviderSubject] != "sub-1" {
		t.Errorf("provider subject = %v, want sub-1", result.User.Metadata[UserMetadataKeyProviderSubject])
	}
	if !result.User.EmailVerified {
		t.Error("EmailVerified = false on a user created from a verified assertion")
	}
}

func TestClaimAllowlistCopiesOnlyNamedClaims(t *testing.T) {
	t.Parallel()
	h := newHarness(t, harnessOptions{allowlist: []string{"groups", "absent"}})

	_, state, binding, _ := h.start(t)

	result, err := h.client.HandleCallbackWithBinding(context.Background(), state, "code", binding)
	if err != nil {
		t.Fatalf("HandleCallbackWithBinding: %v", err)
	}
	if _, ok := result.User.Metadata["groups"]; !ok {
		t.Error("an allow-listed claim was not copied")
	}
	if _, ok := result.User.Metadata["absent"]; ok {
		t.Error("a claim the provider never asserted was invented")
	}
	if _, ok := result.User.Metadata["email"]; ok {
		t.Error("a claim outside the allow-list was copied (F-21)")
	}
}

func TestAllowlistCannotDisplaceTheProviderSubject(t *testing.T) {
	t.Parallel()
	info := &UserInfo{
		Subject:       "sub-1",
		Email:         "user@example.com",
		EmailVerified: true,
		RawClaims: map[string]interface{}{
			UserMetadataKeyProviderSubject: "sub-forged",
		},
	}
	h := newHarness(t, harnessOptions{info: info, allowlist: []string{UserMetadataKeyProviderSubject}})

	_, state, binding, _ := h.start(t)

	result, err := h.client.HandleCallbackWithBinding(context.Background(), state, "code", binding)
	if err != nil {
		t.Fatalf("HandleCallbackWithBinding: %v", err)
	}
	if got := result.User.Metadata[UserMetadataKeyProviderSubject]; got != "sub-1" {
		t.Errorf("provider subject = %v, want the verified sub, not an allow-listed claim of the same name", got)
	}
}

// --- F-20: egress ----------------------------------------------------------

type recordingTransport struct {
	mu     sync.Mutex
	called bool
	base   http.RoundTripper
}

func (t *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.called = true
	t.mu.Unlock()
	return t.base.RoundTrip(req)
}

func (t *recordingTransport) wasCalled() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.called
}

func TestConfiguredHTTPClientPerformsTheExchange(t *testing.T) {
	t.Parallel()
	transport := &recordingTransport{base: http.DefaultTransport}
	h := newHarness(t, harnessOptions{
		httpClient: &http.Client{Transport: transport, Timeout: 5 * time.Second},
	})

	_, state, binding, _ := h.start(t)

	if _, err := h.client.HandleCallbackWithBinding(context.Background(), state, "code", binding); err != nil {
		t.Fatalf("HandleCallbackWithBinding: %v", err)
	}
	if !transport.wasCalled() {
		t.Error("token exchange did not use the configured HTTP client (F-20, CWE-918)")
	}
}

func TestDefaultHTTPClientIsBounded(t *testing.T) {
	t.Parallel()
	client := DefaultHTTPClient()
	if client.Timeout <= 0 {
		t.Error("default HTTP client has no timeout (F-20)")
	}
	if client.Timeout != DefaultHTTPTimeout {
		t.Errorf("timeout = %v, want %v", client.Timeout, DefaultHTTPTimeout)
	}
}

func TestDefaultHTTPClientRefusesAnOversizedBody(t *testing.T) {
	t.Parallel()
	body := strings.Repeat("a", DefaultMaxResponseBytes+1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := io.WriteString(w, body); err != nil {
			return // the client hangs up as soon as the limit trips
		}
	}))
	t.Cleanup(server.Close)

	resp, err := DefaultHTTPClient().Get(server.URL) //nolint:noctx // exercising the transport itself
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Errorf("close body: %v", closeErr)
		}
	})

	if _, err := io.ReadAll(resp.Body); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("read error = %v, want ErrResponseTooLarge (F-20, CWE-400)", err)
	}
}

func TestDefaultHTTPClientAllowsABodyAtTheLimit(t *testing.T) {
	t.Parallel()
	body := strings.Repeat("a", DefaultMaxResponseBytes)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := io.WriteString(w, body); err != nil {
			t.Errorf("write body: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	resp, err := DefaultHTTPClient().Get(server.URL) //nolint:noctx // exercising the transport itself
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Errorf("close body: %v", closeErr)
		}
	})

	read, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(read) != DefaultMaxResponseBytes {
		t.Errorf("read %d bytes, want %d", len(read), DefaultMaxResponseBytes)
	}
}

// --- state, metadata and construction --------------------------------------

func TestScopeOverrideIsAppliedOnceAndKeepsTheEndpoint(t *testing.T) {
	t.Parallel()
	h := newHarness(t, harnessOptions{})

	req, err := h.client.GetAuthorizationURLWithBinding(context.Background(), AuthURLOptions{
		Provider: "acme",
		Scopes:   []string{"openid", "profile", "custom"},
	})
	if err != nil {
		t.Fatalf("GetAuthorizationURLWithBinding: %v", err)
	}
	parsed, err := url.Parse(req.URL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got, want := parsed.Host, "idp.example"; got != want {
		t.Errorf("authorization host = %q, want %q: the endpoint was dropped by the override", got, want)
	}
	if got := parsed.Query().Get("scope"); got != "openid profile custom" {
		t.Errorf("scope = %q, want the override", got)
	}
	if got := parsed.Query().Get("client_id"); got != "client-id" {
		t.Errorf("client_id = %q, want the provider's", got)
	}
	if got := parsed.Query().Get("redirect_uri"); got != "https://app.example/callback" {
		t.Errorf("redirect_uri = %q, want the provider's registered value", got)
	}
	if got := strings.Join(h.provider.cfg.Scopes, " "); got != "openid email" {
		t.Errorf("the provider's own config was mutated: scopes = %q", got)
	}
}

func TestStateMetadataRoundTripsWithoutLibraryKeys(t *testing.T) {
	t.Parallel()
	h := newHarness(t, harnessOptions{})

	req, err := h.client.GetAuthorizationURLWithBinding(context.Background(), AuthURLOptions{
		Provider: "acme",
		Metadata: map[string]interface{}{"tenant": "acme-corp"},
	})
	if err != nil {
		t.Fatalf("GetAuthorizationURLWithBinding: %v", err)
	}
	stored := h.states.peek(req.State)
	h.provider.info.RawClaims["nonce"] = stored.Nonce

	result, err := h.client.HandleCallbackWithBinding(context.Background(), req.State, "code", req.Binding)
	if err != nil {
		t.Fatalf("HandleCallbackWithBinding: %v", err)
	}
	if result.Metadata["tenant"] != "acme-corp" {
		t.Errorf("metadata = %v, want the caller's own value", result.Metadata)
	}
	for key := range result.Metadata {
		if strings.HasPrefix(key, StateMetadataPrefix) {
			t.Errorf("reserved key %q was handed back to the caller", key)
		}
	}
}

func TestCallerMetadataIsNotMutated(t *testing.T) {
	t.Parallel()
	h := newHarness(t, harnessOptions{})

	caller := map[string]interface{}{"tenant": "acme-corp"}
	if _, err := h.client.GetAuthorizationURLWithBinding(context.Background(), AuthURLOptions{
		Provider: "acme",
		Metadata: caller,
	}); err != nil {
		t.Fatalf("GetAuthorizationURLWithBinding: %v", err)
	}
	if len(caller) != 1 {
		t.Errorf("caller metadata = %v, want it untouched", caller)
	}
}

func TestReservedMetadataKeyIsRefused(t *testing.T) {
	t.Parallel()
	h := newHarness(t, harnessOptions{})

	_, err := h.client.GetAuthorizationURLWithBinding(context.Background(), AuthURLOptions{
		Provider: "acme",
		Metadata: map[string]interface{}{StateMetadataKeyPKCEVerifier: "attacker-chosen"},
	})
	if !errors.Is(err, ErrReservedMetadataKey) {
		t.Fatalf("error = %v, want ErrReservedMetadataKey", err)
	}
}

func TestStateIsSingleUse(t *testing.T) {
	t.Parallel()
	h := newHarness(t, harnessOptions{})

	_, state, binding, _ := h.start(t)

	if _, err := h.client.HandleCallbackWithBinding(context.Background(), state, "code", binding); err != nil {
		t.Fatalf("first callback: %v", err)
	}
	_, err := h.client.HandleCallbackWithBinding(context.Background(), state, "code", binding)
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf("replayed callback error = %v, want ErrInvalidState", err)
	}
}

func TestCallbackRejectsEmptyStateOrCode(t *testing.T) {
	t.Parallel()
	h := newHarness(t, harnessOptions{})

	if _, err := h.client.HandleCallback(context.Background(), "", "code"); !errors.Is(err, ErrInvalidState) {
		t.Errorf("empty state error = %v, want ErrInvalidState", err)
	}
	if _, err := h.client.HandleCallback(context.Background(), "state", ""); !errors.Is(err, ErrInvalidState) {
		t.Errorf("empty code error = %v, want ErrInvalidState", err)
	}
}

func TestStateTTLIsBounded(t *testing.T) {
	t.Parallel()
	h := newHarness(t, harnessOptions{})

	req, err := h.client.GetAuthorizationURLWithBinding(context.Background(), AuthURLOptions{Provider: "acme"})
	if err != nil {
		t.Fatalf("GetAuthorizationURLWithBinding: %v", err)
	}
	h.states.mu.Lock()
	ttl := h.states.ttls[req.State]
	h.states.mu.Unlock()
	if ttl != DefaultStateTTL {
		t.Errorf("state TTL = %v, want %v", ttl, DefaultStateTTL)
	}
}

func TestNewClientRejectsDuplicateAndNilProviders(t *testing.T) {
	t.Parallel()
	p := &fakeProvider{name: "acme", cfg: &oauth2.Config{}}

	if _, err := NewClient(Config{Providers: []Provider{p, p}, StateStore: newFakeStateStore()}); err == nil {
		t.Error("a duplicate provider name was accepted; it silently shadows a configuration")
	}
	if _, err := NewClient(Config{Providers: []Provider{nil}, StateStore: newFakeStateStore()}); err == nil {
		t.Error("a nil provider was accepted")
	}
	if _, err := NewClient(Config{Providers: []Provider{p}, StateStore: nil}); err == nil {
		t.Error("a nil state store was accepted")
	}
}

func TestNewClientAcceptsNoUserStore(t *testing.T) {
	t.Parallel()
	client, err := NewClient(Config{
		Providers:  []Provider{&fakeProvider{name: "acme", cfg: &oauth2.Config{}}},
		StateStore: newFakeStateStore(),
	})
	if err != nil {
		t.Fatalf("NewClient without a user store: %v", err)
	}
	if got := client.ListProviders(); len(got) != 1 || got[0] != "acme" {
		t.Errorf("providers = %v, want [acme]", got)
	}
}

func TestUnknownProviderIsRejected(t *testing.T) {
	t.Parallel()
	h := newHarness(t, harnessOptions{})

	if _, err := h.client.GetAuthorizationURL(context.Background(), AuthURLOptions{Provider: "nope"}); !errors.Is(err, ErrProviderNotFound) {
		t.Errorf("error = %v, want ErrProviderNotFound", err)
	}
	if _, err := h.client.GetProvider("nope"); !errors.Is(err, ErrProviderNotFound) {
		t.Errorf("error = %v, want ErrProviderNotFound", err)
	}
}

func TestExchangeFailureIsWrappedNotSwallowed(t *testing.T) {
	t.Parallel()
	h := newHarness(t, harnessOptions{})
	h.tokens.Close() // the token endpoint is gone

	_, state, binding, _ := h.start(t)

	_, err := h.client.HandleCallbackWithBinding(context.Background(), state, "code", binding)
	if !errors.Is(err, ErrExchangeFailed) {
		t.Fatalf("error = %v, want ErrExchangeFailed", err)
	}
	if !strings.Contains(err.Error(), "connect") && !strings.Contains(err.Error(), "refused") {
		t.Logf("wrapped cause: %v", err) // cause text is platform-dependent; presence is what matters
	}
}

func TestUserInfoFailureIsWrapped(t *testing.T) {
	t.Parallel()
	h := newHarness(t, harnessOptions{})
	sentinel := errors.New("id token signature invalid")
	h.provider.extractErr = sentinel

	_, state, binding, _ := h.start(t)

	_, err := h.client.HandleCallbackWithBinding(context.Background(), state, "code", binding)
	if !errors.Is(err, ErrUserInfoFailed) {
		t.Fatalf("error = %v, want ErrUserInfoFailed", err)
	}
	if !errors.Is(err, sentinel) {
		t.Error("the provider's own error was discarded")
	}
}

func TestRandomValuesAreDistinctAndSized(t *testing.T) {
	t.Parallel()
	seen := make(map[string]struct{}, 64)
	for range 64 {
		v, err := randomValue(stateEntropyBytes)
		if err != nil {
			t.Fatalf("randomValue: %v", err)
		}
		if len(v) < 43 { // 32 bytes, base64url without padding
			t.Fatalf("value %q is shorter than 256 bits of entropy", v)
		}
		if _, dup := seen[v]; dup {
			t.Fatalf("randomValue repeated %q", v)
		}
		seen[v] = struct{}{}
	}
}
