package oidc

// Adversarial tests for the OIDC relying-party client.
//
// Every test in this file is named for the attack it denies rather than for the
// function it exercises, and every one is written so that it fails if the
// corresponding fix in docs/security-hardening.md is reverted.
//
// The fixtures are hostile by construction. The identity provider is treated as
// threat-model adversary 2: a malicious or compromised IdP, or a tenant
// administrator who legitimately controls their own connection, able to assert
// any claim set it likes. The browser is treated as adversary 1: able to
// present any state, code, or cookie value, to replay, to truncate, and to
// reorder. The state store is the real storage.InMemoryOIDCStateStore, so the
// one-time-use and expiry semantics under test are the shipped ones and not a
// mock's approximation of them.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/meysam81/go-auth/storage"
	"golang.org/x/oauth2"
)

const (
	// advProviderName is the name the client registers the provider under. The
	// distinction between this and whatever the provider asserts about itself
	// is load-bearing for TestOIDC_AssertedProviderNameCannotAdoptForeignAccount.
	advProviderName = "acme"

	// advForeignProviderName is a second registered connection, standing in for
	// the other tenant in an identity-provider mix-up (RFC 9700 section 4.4).
	advForeignProviderName = "ghost"

	// advCode is the authorization code the callback presents. In several tests
	// it is an attacker-chosen value that must never be redeemed.
	advCode = "authorization-code-under-test"

	advVictimEmail = "victim@example.com"
	advVictimSub   = "provider-subject-victim"
)

// The fixtures below stand in for the three parties the package must not trust:
// the identity provider, the application's own store, and the browser.
var (
	_ Provider               = (*advProvider)(nil)
	_ storage.OIDCStateStore = (*advStateStore)(nil)
	_ storage.UserStore      = (*advUserStore)(nil)

	errAdvStoreUnavailable    = errors.New("adversarial: user store is unavailable")
	errAdvLinkPolicyExploded  = errors.New("adversarial: link policy could not decide")
	errAdvNoAssertionWired    = errors.New("adversarial: no provider assertion wired for this test")
	errAdvUnexpectedTokenCall = errors.New("adversarial: token endpoint must not have been reached")
)

// --- hostile fixtures -------------------------------------------------------

// advProvider is an identity provider under the test's control. Whatever the
// test sets is asserted verbatim, including claim sets no honest provider would
// ever emit.
type advProvider struct {
	name  string
	cfg   *oauth2.Config
	oidcp *oidc.Provider

	mu      sync.Mutex
	extract func(context.Context, *oauth2.Token) (*UserInfo, error)
	calls   atomic.Int64
}

func (p *advProvider) Name() string                    { return p.name }
func (p *advProvider) GetOAuth2Config() *oauth2.Config { return p.cfg }
func (p *advProvider) GetOIDCProvider() *oidc.Provider { return p.oidcp }

func (p *advProvider) ExtractUserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	p.calls.Add(1)
	p.mu.Lock()
	fn := p.extract
	p.mu.Unlock()
	if fn == nil {
		return nil, errAdvNoAssertionWired
	}
	return fn(ctx, token)
}

func (p *advProvider) setExtract(fn func(context.Context, *oauth2.Token) (*UserInfo, error)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.extract = fn
}

// advStateStore decorates the real storage.InMemoryOIDCStateStore so a test can
// see what was written without consuming it, count reads, and — for the
// corrupt-record cases only — rewrite the record on the way out, which models a
// state store whose contents were tampered with or written by another library.
type advStateStore struct {
	inner storage.OIDCStateStore

	mu      sync.Mutex
	seen    map[string]*storage.OIDCState
	ttls    map[string]time.Duration
	rewrite func(*storage.OIDCState)

	gets atomic.Int64
}

func newAdvStateStore() *advStateStore {
	return &advStateStore{
		inner: storage.NewInMemoryOIDCStateStore(),
		seen:  make(map[string]*storage.OIDCState),
		ttls:  make(map[string]time.Duration),
	}
}

func (s *advStateStore) StoreState(ctx context.Context, state string, data *storage.OIDCState, ttl time.Duration) error {
	if err := s.inner.StoreState(ctx, state, data, ttl); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen[state] = advCloneState(data)
	s.ttls[state] = ttl
	return nil
}

func (s *advStateStore) GetState(ctx context.Context, state string) (*storage.OIDCState, error) {
	s.gets.Add(1)
	data, err := s.inner.GetState(ctx, state)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	fn := s.rewrite
	s.mu.Unlock()
	if fn != nil && data != nil {
		fn(data)
	}
	return data, nil
}

func (s *advStateStore) DeleteState(ctx context.Context, state string) error {
	return s.inner.DeleteState(ctx, state)
}

// peek returns a copy of the record as it was written, without consuming it.
func (s *advStateStore) peek(state string) *storage.OIDCState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return advCloneState(s.seen[state])
}

// count reports how many distinct authorization requests were persisted. A URL
// built twice, or a state minted twice, shows up here.
func (s *advStateStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

func (s *advStateStore) ttlOf(state string) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ttls[state]
}

func (s *advStateStore) onRead(fn func(*storage.OIDCState)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rewrite = fn
}

// inject writes a record the client never produced: an attacker-planted or
// foreign-writer state.
func (s *advStateStore) inject(t *testing.T, state string, data *storage.OIDCState, ttl time.Duration) {
	t.Helper()
	if err := s.StoreState(context.Background(), state, data, ttl); err != nil {
		t.Fatalf("inject state %q: %v", state, err)
	}
}

func advCloneState(in *storage.OIDCState) *storage.OIDCState {
	if in == nil {
		return nil
	}
	out := *in
	if in.Metadata != nil {
		out.Metadata = make(map[string]interface{}, len(in.Metadata))
		for k, v := range in.Metadata {
			out.Metadata[k] = v
		}
	}
	return &out
}

// advUserStore wraps the real storage.InMemoryUserStore so a test can count
// account creations and, where the test is about a badly-behaved store, replace
// the email lookup with something the library must survive.
type advUserStore struct {
	inner *storage.InMemoryUserStore

	mu         sync.Mutex
	getByEmail func(context.Context, string) (*storage.User, error)

	creates atomic.Int64
}

func newAdvUserStore() *advUserStore {
	return &advUserStore{inner: storage.NewInMemoryUserStore()}
}

func (s *advUserStore) CreateUser(ctx context.Context, user *storage.User) error {
	s.creates.Add(1)
	return s.inner.CreateUser(ctx, user)
}

func (s *advUserStore) GetUserByID(ctx context.Context, id string) (*storage.User, error) {
	return s.inner.GetUserByID(ctx, id)
}

func (s *advUserStore) GetUserByEmail(ctx context.Context, email string) (*storage.User, error) {
	s.mu.Lock()
	fn := s.getByEmail
	s.mu.Unlock()
	if fn != nil {
		return fn(ctx, email)
	}
	return s.inner.GetUserByEmail(ctx, email)
}

func (s *advUserStore) GetUserByUsername(ctx context.Context, username string) (*storage.User, error) {
	return s.inner.GetUserByUsername(ctx, username)
}

func (s *advUserStore) UpdateUser(ctx context.Context, user *storage.User) error {
	return s.inner.UpdateUser(ctx, user)
}

func (s *advUserStore) DeleteUser(ctx context.Context, id string) error {
	return s.inner.DeleteUser(ctx, id)
}

// seed installs an account that predates the flow under test — the account an
// nOAuth-class assertion tries to take over.
func (s *advUserStore) seed(t *testing.T, user *storage.User) *storage.User {
	t.Helper()
	if err := s.inner.CreateUser(context.Background(), user); err != nil {
		t.Fatalf("seed user %q: %v", user.Email, err)
	}
	return user
}

func (s *advUserStore) created() int64 { return s.creates.Load() }

func (s *advUserStore) failEmailLookup(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.getByEmail = func(context.Context, string) (*storage.User, error) { return nil, err }
}

// returnNilForKnownEmail models a store that reports success and hands back no
// row — a contract violation the library must fail closed on rather than
// dereference.
func (s *advUserStore) returnNilForKnownEmail() {
	s.mu.Lock()
	defer s.mu.Unlock()
	//nolint:nilnil // a store reporting success with no row is the contract violation under test.
	s.getByEmail = func(context.Context, string) (*storage.User, error) { return nil, nil }
}

// advTokenEndpoint is the provider's token endpoint. It records every exchange
// so a test can assert both what was proved to it and that it was never reached
// at all when a control upstream should have stopped the callback.
type advTokenEndpoint struct {
	*httptest.Server

	mu    sync.Mutex
	forms []url.Values
	calls atomic.Int64
}

func newAdvTokenEndpoint(t *testing.T) *advTokenEndpoint {
	t.Helper()
	ep := &advTokenEndpoint{}
	ep.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ep.calls.Add(1)
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := r.ParseForm(); err != nil {
			t.Errorf("token endpoint: parse form: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ep.mu.Lock()
		ep.forms = append(ep.forms, r.Form)
		ep.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		body := `{"access_token":"opaque-access-token","token_type":"Bearer","expires_in":3600,` +
			`"id_token":"header.payload.signature"}`
		if _, err := io.WriteString(w, body); err != nil {
			t.Errorf("token endpoint: write response: %v", err)
		}
	}))
	t.Cleanup(ep.Close)
	return ep
}

func (ep *advTokenEndpoint) hits() int64 { return ep.calls.Load() }

func (ep *advTokenEndpoint) lastForm(t *testing.T) url.Values {
	t.Helper()
	ep.mu.Lock()
	defer ep.mu.Unlock()
	if len(ep.forms) == 0 {
		t.Fatalf("token endpoint was never reached")
	}
	return ep.forms[len(ep.forms)-1]
}

// --- flow harness -----------------------------------------------------------

type advOptions struct {
	// oauth2Only registers a provider with no *oidc.Provider, so no nonce is
	// requested and none can be verified.
	oauth2Only bool

	// claimsOnly leaves Config.UserStore nil: the v2 shape, where the library
	// reports verified claims and touches no account.
	claimsOnly bool

	linkPolicy LinkPolicy
	allowlist  []string

	// createPolicy overrides the harness default of AllowAccountCreation, and
	// noCreatePolicy removes it so the shipped default — a nil policy refuses to
	// provision — is what the test exercises.
	createPolicy   CreatePolicy
	noCreatePolicy bool

	// stateStore replaces the record-keeping half of the state store, so a test
	// can run the whole flow against a backend that persists only some of the
	// fields the library writes.
	stateStore storage.OIDCStateStore

	// withForeignProvider registers a second connection so a mix-up between two
	// tenants' providers can be attempted.
	withForeignProvider bool

	// withBrokenProvider registers a provider that supplies no OAuth2 config.
	withBrokenProvider bool
}

type advFlow struct {
	client   *Client
	states   *advStateStore
	users    *advUserStore
	provider *advProvider
	foreign  *advProvider
	tokens   *advTokenEndpoint
	foreignT *advTokenEndpoint
}

func newAdvFlow(t *testing.T, opts advOptions) *advFlow {
	t.Helper()

	tokens := newAdvTokenEndpoint(t)
	provider := advNewProvider(t, advProviderName, tokens.URL, !opts.oauth2Only)

	f := &advFlow{
		states:   newAdvStateStore(),
		provider: provider,
		tokens:   tokens,
	}
	if opts.stateStore != nil {
		f.states.inner = opts.stateStore
	}

	providers := []Provider{provider}
	if opts.withForeignProvider {
		f.foreignT = newAdvTokenEndpoint(t)
		f.foreign = advNewProvider(t, advForeignProviderName, f.foreignT.URL, true)
		providers = append(providers, f.foreign)
	}
	if opts.withBrokenProvider {
		providers = append(providers, &advProvider{name: "misconfigured"})
	}

	createPolicy := opts.createPolicy
	if createPolicy == nil && !opts.noCreatePolicy {
		createPolicy = AllowAccountCreation
	}

	cfg := Config{
		Providers:      providers,
		StateStore:     f.states,
		RedirectURL:    "https://app.example/home",
		LinkPolicy:     opts.linkPolicy,
		CreatePolicy:   createPolicy,
		ClaimAllowlist: opts.allowlist,
	}
	if !opts.claimsOnly {
		f.users = newAdvUserStore()
		cfg.UserStore = f.users
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	f.client = client
	return f
}

func advNewProvider(t *testing.T, name, tokenURL string, withOIDC bool) *advProvider {
	t.Helper()
	p := &advProvider{
		name: name,
		cfg: &oauth2.Config{
			ClientID:     "client-id-" + name,
			ClientSecret: "client-secret-" + name,
			RedirectURL:  "https://app.example/callback/" + name,
			Scopes:       []string{"openid", "email", "profile"},
			Endpoint: oauth2.Endpoint{
				AuthURL:   "https://idp.example/" + name + "/authorize",
				TokenURL:  tokenURL,
				AuthStyle: oauth2.AuthStyleInParams,
			},
		},
	}
	if withOIDC {
		p.oidcp = (&oidc.ProviderConfig{
			IssuerURL: "https://idp.example/" + name,
			AuthURL:   p.cfg.Endpoint.AuthURL,
			TokenURL:  tokenURL,
			JWKSURL:   "https://idp.example/" + name + "/jwks",
		}).NewProvider(context.Background())
	}
	return p
}

// begin starts a bound flow and wires the provider to behave honestly, echoing
// back the nonce this process requested. Tests then replace the assertion with
// something worse.
func (f *advFlow) begin(t *testing.T, opts AuthURLOptions) *AuthorizationRequest {
	t.Helper()
	req := f.beginRaw(t, opts)
	f.idpAsserts(advHonestUserInfo(), map[string]interface{}{"nonce": f.nonceOf(req.State)})
	return req
}

// beginRaw starts a bound flow without touching the provider's assertion, for
// tests that need a second, independent flow.
func (f *advFlow) beginRaw(t *testing.T, opts AuthURLOptions) *AuthorizationRequest {
	t.Helper()
	if opts.Provider == "" {
		opts.Provider = advProviderName
	}
	req, err := f.client.GetAuthorizationURLWithBinding(context.Background(), opts)
	if err != nil {
		t.Fatalf("GetAuthorizationURLWithBinding: %v", err)
	}
	return req
}

func (f *advFlow) nonceOf(state string) string {
	rec := f.states.peek(state)
	if rec == nil {
		return ""
	}
	return rec.Nonce
}

func (f *advFlow) verifierOf(t *testing.T, state string) string {
	t.Helper()
	rec := f.states.peek(state)
	if rec == nil {
		t.Fatalf("state %q was never stored", state)
	}
	v, ok := rec.Metadata[StateMetadataKeyPKCEVerifier].(string)
	if !ok || v == "" {
		t.Fatalf("state %q carries no PKCE verifier: %#v", state, rec.Metadata)
	}
	return v
}

func (f *advFlow) bindingDigestOf(t *testing.T, state string) string {
	t.Helper()
	rec := f.states.peek(state)
	if rec == nil {
		t.Fatalf("state %q was never stored", state)
	}
	d, ok := rec.Metadata[StateMetadataKeyBinding].(string)
	if !ok || d == "" {
		t.Fatalf("state %q carries no binding digest: %#v", state, rec.Metadata)
	}
	return d
}

// idpAsserts installs the claim set the provider will assert. claims is used
// verbatim as RawClaims, so a test can omit, retype, or forge any of them. A
// fresh UserInfo is produced per call, because the client mutates it.
func (f *advFlow) idpAsserts(info UserInfo, claims map[string]interface{}) {
	f.provider.setExtract(func(context.Context, *oauth2.Token) (*UserInfo, error) {
		out := info
		if claims == nil {
			out.RawClaims = nil
			return &out, nil
		}
		copied := make(map[string]interface{}, len(claims))
		for k, v := range claims {
			if k == "nonce" {
				if s, ok := v.(string); ok && s == "" {
					continue // an absent nonce, not an empty one
				}
			}
			copied[k] = v
		}
		out.RawClaims = copied
		return &out, nil
	})
}

func (f *advFlow) callback(state, binding string) (*CallbackResult, error) {
	return f.client.HandleCallbackWithBinding(context.Background(), state, advCode, binding)
}

func advHonestUserInfo() UserInfo {
	return UserInfo{
		Subject:       advVictimSub,
		Email:         advVictimEmail,
		EmailVerified: true,
		Name:          "Victim Example",
		Username:      "victim",
	}
}

// --- assertion helpers ------------------------------------------------------

func advWantErr(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("error = %v, want one wrapping %v", err, target)
	}
}

func advWantNoResult(t *testing.T, result *CallbackResult) {
	t.Helper()
	if result != nil {
		t.Fatalf("a refused callback returned a result: %#v", result)
	}
}

func advWantNoExchange(t *testing.T, ep *advTokenEndpoint) {
	t.Helper()
	if hits := ep.hits(); hits != 0 {
		t.Fatalf("%v: the authorization code was redeemed %d time(s) before the control passed",
			errAdvUnexpectedTokenCall, hits)
	}
}

// advS256Challenge recomputes the PKCE challenge independently of the library,
// so the test proves the transform is S256 rather than trusting the same helper
// the implementation uses (RFC 7636 section 4.2).
func advS256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// advRandomValue returns attacker-supplied entropy. crypto/rand only.
func advRandomValue(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// advFlipLast returns s with its final byte changed, preserving length so a
// comparison cannot reject it on size alone.
func advFlipLast(s string) string {
	if s == "" {
		return "x"
	}
	b := []byte(s)
	if b[len(b)-1] == 'A' {
		b[len(b)-1] = 'B'
	} else {
		b[len(b)-1] = 'A'
	}
	return string(b)
}

// --- F-01: nOAuth, the unverified-email account takeover ---------------------

// TestOIDC_UnverifiedEmailNeverResolvesToAnExistingAccount covers the defect
// published as CVE-2023-28131 ("nOAuth") and described in RFC 9700 section 4:
// an identity provider that can be induced to assert an arbitrary, unverified
// email address takes over whatever account carries that address. The claim is
// attacker-chosen in every bring-your-own-connection deployment, so it can
// never be an identity. Reverting the EmailVerified check makes every row here
// resolve to the seeded victim.
func TestOIDC_UnverifiedEmailNeverResolvesToAnExistingAccount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		existing *storage.User
	}{
		{
			name: "password account with no provider",
			existing: &storage.User{
				ID: "victim-local", Email: advVictimEmail, EmailVerified: true, Provider: "local",
			},
		},
		{
			name: "account created by this very provider and subject",
			existing: &storage.User{
				ID: "victim-same", Email: advVictimEmail, EmailVerified: true, Provider: advProviderName,
				Metadata: map[string]interface{}{UserMetadataKeyProviderSubject: advVictimSub},
			},
		},
		{
			name: "account created by another provider",
			existing: &storage.User{
				ID: "victim-other", Email: advVictimEmail, EmailVerified: true, Provider: "google",
				Metadata: map[string]interface{}{UserMetadataKeyProviderSubject: advVictimSub},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var policyCalls atomic.Int64
			f := newAdvFlow(t, advOptions{
				linkPolicy: func(context.Context, *storage.User, *UserInfo) (bool, error) {
					policyCalls.Add(1)
					return true, nil // a permissive application must still not save this
				},
			})
			f.users.seed(t, tc.existing)

			req := f.begin(t, AuthURLOptions{})
			info := advHonestUserInfo()
			info.EmailVerified = false
			f.idpAsserts(info, map[string]interface{}{"nonce": f.nonceOf(req.State)})

			result, err := f.callback(req.State, req.Binding)
			advWantErr(t, err, ErrEmailNotVerified)
			advWantNoResult(t, result)

			if got := f.users.created(); got != 0 {
				t.Errorf("an unverified assertion created %d account(s), want 0", got)
			}
			// The verification check must run before the link decision. A
			// policy that never sees the assertion cannot be tricked into
			// approving it.
			if got := policyCalls.Load(); got != 0 {
				t.Errorf("LinkPolicy was consulted %d time(s) for an unverified email, want 0", got)
			}
		})
	}
}

// TestOIDC_UnverifiedEmailAlsoRefusesToProvision checks the other half of the
// nOAuth class: with no pre-existing account, an unverified email must not mint
// one either. Provisioning off an unverified claim lets an adversary plant the
// account that a later, honest sign-in then adopts.
func TestOIDC_UnverifiedEmailAlsoRefusesToProvision(t *testing.T) {
	t.Parallel()

	f := newAdvFlow(t, advOptions{})
	req := f.begin(t, AuthURLOptions{})
	info := advHonestUserInfo()
	info.EmailVerified = false
	f.idpAsserts(info, map[string]interface{}{"nonce": f.nonceOf(req.State)})

	result, err := f.callback(req.State, req.Binding)
	advWantErr(t, err, ErrEmailNotVerified)
	advWantNoResult(t, result)
	if got := f.users.created(); got != 0 {
		t.Fatalf("created %d account(s) from an unverified email, want 0", got)
	}
}

// TestOIDC_ForeignSubjectNeverSilentlyAdoptsAnAccount asserts that matching on
// the email address alone is never enough. OIDC Core section 2 makes sub the
// only identifier a provider promises not to reassign; an email address is
// re-assignable and, across two providers, not even unique. Each row is a
// shape the pre-fix GetUserByEmail-and-return path would have adopted.
func TestOIDC_ForeignSubjectNeverSilentlyAdoptsAnAccount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		existing *storage.User
		wantErr  error
	}{
		{
			name:     "local password account, no provider recorded",
			existing: &storage.User{ID: "u1", Email: advVictimEmail, Provider: "local"},
			wantErr:  ErrAccountLinkRequired,
		},
		{
			name: "same provider, different subject",
			existing: &storage.User{ID: "u2", Email: advVictimEmail, Provider: advProviderName,
				Metadata: map[string]interface{}{UserMetadataKeyProviderSubject: "some-other-subject"}},
			wantErr: ErrAccountLinkRequired,
		},
		{
			name: "different provider, identical subject",
			existing: &storage.User{ID: "u3", Email: advVictimEmail, Provider: "google",
				Metadata: map[string]interface{}{UserMetadataKeyProviderSubject: advVictimSub}},
			wantErr: ErrAccountLinkRequired,
		},
		{
			name: "no provider recorded at all",
			existing: &storage.User{ID: "u4", Email: advVictimEmail,
				Metadata: map[string]interface{}{UserMetadataKeyProviderSubject: advVictimSub}},
			wantErr: ErrAccountLinkRequired,
		},
		{
			// The only shape that adopts without a recorded subject, and it
			// adopts once: the account was provisioned by this same registered
			// connection before subjects were recorded at all, so refusing it
			// locks its owner out for good. See
			// TestOIDC_AccountPredatingSubjectRecordingIsPinnedOnFirstSignIn.
			name:     "provider matches but no subject was ever recorded",
			existing: &storage.User{ID: "u5", Email: advVictimEmail, Provider: advProviderName},
			wantErr:  nil,
		},
		{
			name: "recorded subject is the empty string",
			existing: &storage.User{ID: "u6", Email: advVictimEmail, Provider: advProviderName,
				Metadata: map[string]interface{}{UserMetadataKeyProviderSubject: ""}},
			wantErr: ErrAccountLinkRequired,
		},
		{
			name: "recorded subject is not a string, as a JSON round trip can produce",
			existing: &storage.User{ID: "u7", Email: advVictimEmail, Provider: advProviderName,
				Metadata: map[string]interface{}{UserMetadataKeyProviderSubject: float64(1)}},
			wantErr: ErrAccountLinkRequired,
		},
		{
			name: "subject differs only in case",
			existing: &storage.User{ID: "u8", Email: advVictimEmail, Provider: advProviderName,
				Metadata: map[string]interface{}{UserMetadataKeyProviderSubject: strings.ToUpper(advVictimSub)}},
			wantErr: ErrAccountLinkRequired,
		},
		{
			name: "asserted subject is a prefix of the recorded one",
			existing: &storage.User{ID: "u9", Email: advVictimEmail, Provider: advProviderName,
				Metadata: map[string]interface{}{UserMetadataKeyProviderSubject: advVictimSub + "-extra"}},
			wantErr: ErrAccountLinkRequired,
		},
		{
			name: "recorded subject carries trailing whitespace",
			existing: &storage.User{ID: "u10", Email: advVictimEmail, Provider: advProviderName,
				Metadata: map[string]interface{}{UserMetadataKeyProviderSubject: advVictimSub + " "}},
			wantErr: ErrAccountLinkRequired,
		},
		{
			name: "same provider and same subject is the one case that adopts",
			existing: &storage.User{ID: "u11", Email: advVictimEmail, Provider: advProviderName,
				Metadata: map[string]interface{}{UserMetadataKeyProviderSubject: advVictimSub}},
			wantErr: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newAdvFlow(t, advOptions{})
			f.users.seed(t, tc.existing)

			req := f.begin(t, AuthURLOptions{})
			result, err := f.callback(req.State, req.Binding)

			if tc.wantErr != nil {
				advWantErr(t, err, tc.wantErr)
				advWantNoResult(t, result)
				if got := f.users.created(); got != 0 {
					t.Errorf("a refused link created %d account(s), want 0", got)
				}
				return
			}

			if err != nil {
				t.Fatalf("a matching provider and subject must adopt: %v", err)
			}
			if result.User == nil || result.User.ID != tc.existing.ID {
				t.Fatalf("adopted user = %#v, want ID %q", result.User, tc.existing.ID)
			}
			if result.IsNewUser {
				t.Errorf("IsNewUser = true for an adopted account")
			}
			if got := f.users.created(); got != 0 {
				t.Errorf("adoption created %d account(s), want 0", got)
			}
		})
	}
}

// TestOIDC_AssertedProviderNameCannotAdoptForeignAccount denies the
// self-naming variant of the nOAuth class. A malicious provider implementation
// asserts UserInfo.Provider itself; if the client believed that field, the
// connection registered as "acme" could claim to be "google" and adopt every
// account Google created. The name of the connection the flow was started
// against — recorded in the state record — is the only trustworthy one.
func TestOIDC_AssertedProviderNameCannotAdoptForeignAccount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		existingProvider string
		wantErr          error
	}{
		{name: "spoofing another connection's name", existingProvider: "google", wantErr: ErrAccountLinkRequired},
		{name: "the connection the flow actually used", existingProvider: advProviderName, wantErr: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newAdvFlow(t, advOptions{})
			f.users.seed(t, &storage.User{
				ID: "victim", Email: advVictimEmail, EmailVerified: true,
				Provider: tc.existingProvider,
				Metadata: map[string]interface{}{UserMetadataKeyProviderSubject: advVictimSub},
			})

			req := f.beginRaw(t, AuthURLOptions{})
			info := advHonestUserInfo()
			info.Provider = "google" // the provider lies about who it is
			f.idpAsserts(info, map[string]interface{}{"nonce": f.nonceOf(req.State)})

			result, err := f.callback(req.State, req.Binding)
			if tc.wantErr != nil {
				advWantErr(t, err, tc.wantErr)
				advWantNoResult(t, result)
				return
			}
			if err != nil {
				t.Fatalf("callback: %v", err)
			}
			if result.UserInfo.Provider != advProviderName {
				t.Fatalf("UserInfo.Provider = %q, want the registered connection %q — a provider "+
					"must not be able to name itself", result.UserInfo.Provider, advProviderName)
			}
		})
	}
}

// TestOIDC_AssertionWithoutSubjectIsRefused: sub is REQUIRED by OIDC Core
// section 2. An assertion without one names no identity, and the pre-fix code
// would have keyed on the email claim alone. The refusal must hold on both the
// find-or-create path and the claims-only path, because the claims-only caller
// is about to key its own records on a subject that is not there.
func TestOIDC_AssertionWithoutSubjectIsRefused(t *testing.T) {
	t.Parallel()

	for _, claimsOnly := range []bool{false, true} {
		name := "with a user store"
		if claimsOnly {
			name = "claims only, no user store"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newAdvFlow(t, advOptions{claimsOnly: claimsOnly})
			req := f.beginRaw(t, AuthURLOptions{})
			info := advHonestUserInfo()
			info.Subject = ""
			f.idpAsserts(info, map[string]interface{}{
				"nonce": f.nonceOf(req.State),
				"sub":   "", // present in the raw claims, still empty
			})

			result, err := f.callback(req.State, req.Binding)
			advWantErr(t, err, ErrMissingSubject)
			advWantNoResult(t, result)
			if !claimsOnly && f.users.created() != 0 {
				t.Fatalf("a subject-less assertion created an account")
			}
		})
	}
}

// TestOIDC_AssertionWithoutEmailIsRefusedByTheResolvingPath: the compatibility
// find-or-create path is keyed on the email address, so an absent one cannot
// resolve an identity and would otherwise mint an unbounded number of accounts
// — one per sign-in, all indistinguishable.
func TestOIDC_AssertionWithoutEmailIsRefusedByTheResolvingPath(t *testing.T) {
	t.Parallel()

	f := newAdvFlow(t, advOptions{})
	req := f.beginRaw(t, AuthURLOptions{})
	info := advHonestUserInfo()
	info.Email = ""
	f.idpAsserts(info, map[string]interface{}{"nonce": f.nonceOf(req.State)})

	result, err := f.callback(req.State, req.Binding)
	advWantErr(t, err, ErrMissingEmail)
	advWantNoResult(t, result)
	if got := f.users.created(); got != 0 {
		t.Fatalf("created %d account(s) with no email address, want 0", got)
	}
}

// TestOIDC_LinkPolicyIsTheOnlyDoorToACrossProviderLink pins the hook's
// contract: true permits the link, false refuses it, and an error aborts the
// callback rather than defaulting to either. A hook that fails open is a hook
// that reintroduces the finding it exists to gate.
func TestOIDC_LinkPolicyIsTheOnlyDoorToACrossProviderLink(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		policy    LinkPolicy
		nilPolicy bool
		wantErr   error
		wantLink  bool
	}{
		{
			name:      "no policy configured refuses",
			nilPolicy: true,
			wantErr:   ErrAccountLinkRequired,
		},
		{
			name:    "policy returning false refuses",
			policy:  func(context.Context, *storage.User, *UserInfo) (bool, error) { return false, nil },
			wantErr: ErrAccountLinkRequired,
		},
		{
			name:    "policy returning an error aborts",
			policy:  func(context.Context, *storage.User, *UserInfo) (bool, error) { return false, errAdvLinkPolicyExploded },
			wantErr: errAdvLinkPolicyExploded,
		},
		{
			name: "policy erroring while also returning true still aborts",
			policy: func(context.Context, *storage.User, *UserInfo) (bool, error) {
				return true, errAdvLinkPolicyExploded
			},
			wantErr: errAdvLinkPolicyExploded,
		},
		{
			name:     "policy returning true permits",
			policy:   func(context.Context, *storage.User, *UserInfo) (bool, error) { return true, nil },
			wantLink: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := advOptions{}
			if !tc.nilPolicy {
				opts.linkPolicy = tc.policy
			}
			f := newAdvFlow(t, opts)
			f.users.seed(t, &storage.User{
				ID: "victim", Email: advVictimEmail, EmailVerified: true, Provider: "google",
				Metadata: map[string]interface{}{UserMetadataKeyProviderSubject: "google-subject"},
			})

			req := f.begin(t, AuthURLOptions{})
			result, err := f.callback(req.State, req.Binding)

			if !tc.wantLink {
				advWantErr(t, err, tc.wantErr)
				advWantNoResult(t, result)
				if got := f.users.created(); got != 0 {
					t.Fatalf("a refused link created %d account(s), want 0", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("an authorized link must succeed: %v", err)
			}
			if result.User == nil || result.User.ID != "victim" {
				t.Fatalf("linked user = %#v, want the existing account", result.User)
			}
			if result.IsNewUser {
				t.Errorf("IsNewUser = true for a linked account")
			}
			if got := f.users.created(); got != 0 {
				t.Errorf("a link created %d account(s), want 0", got)
			}
		})
	}
}

// TestOIDC_LinkPolicySeesTheAccountItIsBeingAskedToLink: a policy that is
// handed the wrong account, or an assertion stripped of the fields it needs,
// cannot make the decision the library delegated to it. It must also not be
// consulted when nothing needs deciding, since a spurious prompt trains the
// application to approve.
func TestOIDC_LinkPolicySeesTheAccountItIsBeingAskedToLink(t *testing.T) {
	t.Parallel()

	type capture struct {
		existing *storage.User
		info     *UserInfo
	}
	var (
		mu    sync.Mutex
		seen  []capture
		calls atomic.Int64
	)
	policy := func(_ context.Context, existing *storage.User, info *UserInfo) (bool, error) {
		calls.Add(1)
		mu.Lock()
		seen = append(seen, capture{existing: existing, info: info})
		mu.Unlock()
		return true, nil
	}

	f := newAdvFlow(t, advOptions{linkPolicy: policy})
	f.users.seed(t, &storage.User{
		ID: "victim", Email: advVictimEmail, EmailVerified: true, Provider: "google",
		Metadata: map[string]interface{}{UserMetadataKeyProviderSubject: "google-subject"},
	})

	req := f.begin(t, AuthURLOptions{})
	if _, err := f.callback(req.State, req.Binding); err != nil {
		t.Fatalf("callback: %v", err)
	}

	if got := calls.Load(); got != 1 {
		t.Fatalf("LinkPolicy called %d time(s), want exactly 1", got)
	}
	mu.Lock()
	got := seen[0]
	mu.Unlock()
	if got.existing == nil || got.existing.ID != "victim" {
		t.Errorf("LinkPolicy saw existing = %#v, want the account being adopted", got.existing)
	}
	if got.info == nil || got.info.Subject != advVictimSub {
		t.Errorf("LinkPolicy saw info = %#v, want the asserted subject %q", got.info, advVictimSub)
	}
	if got.info != nil && got.info.Provider != advProviderName {
		t.Errorf("LinkPolicy saw provider %q, want the registered connection %q", got.info.Provider, advProviderName)
	}

	// A second flow whose identity already matches must not consult the policy.
	f2 := newAdvFlow(t, advOptions{linkPolicy: policy})
	f2.users.seed(t, &storage.User{
		ID: "same", Email: advVictimEmail, EmailVerified: true, Provider: advProviderName,
		Metadata: map[string]interface{}{UserMetadataKeyProviderSubject: advVictimSub},
	})
	before := calls.Load()
	req2 := f2.begin(t, AuthURLOptions{})
	if _, err := f2.callback(req2.State, req2.Binding); err != nil {
		t.Fatalf("matching identity callback: %v", err)
	}
	if after := calls.Load(); after != before {
		t.Fatalf("LinkPolicy was consulted %d extra time(s) for an already-matching identity", after-before)
	}
}

// TestOIDC_HostileUserStoreCannotForceAnAdoption: the store is the application's
// code and can be wrong. A store that reports success and returns no row must
// fail closed rather than be read as "no such account" (which provisions a
// duplicate) or dereferenced (which panics the callback handler). A store that
// fails for any reason other than ErrNotFound must not fall through to account
// creation, because "the database is down" is not "this person is new".
func TestOIDC_HostileUserStoreCannotForceAnAdoption(t *testing.T) {
	t.Parallel()

	t.Run("store returns a nil user with a nil error", func(t *testing.T) {
		t.Parallel()

		f := newAdvFlow(t, advOptions{})
		f.users.returnNilForKnownEmail()

		req := f.begin(t, AuthURLOptions{})
		result, err := f.callback(req.State, req.Binding)
		advWantErr(t, err, ErrAccountLinkRequired)
		advWantNoResult(t, result)
		if got := f.users.created(); got != 0 {
			t.Fatalf("a nil row was read as 'no account' and created %d account(s)", got)
		}
	})

	t.Run("store fails with something other than not-found", func(t *testing.T) {
		t.Parallel()

		f := newAdvFlow(t, advOptions{})
		f.users.failEmailLookup(errAdvStoreUnavailable)

		req := f.begin(t, AuthURLOptions{})
		result, err := f.callback(req.State, req.Binding)
		advWantErr(t, err, errAdvStoreUnavailable)
		advWantNoResult(t, result)
		if got := f.users.created(); got != 0 {
			t.Fatalf("a store failure fell through to creation and made %d account(s)", got)
		}
	})
}

// --- F-18: nonce ------------------------------------------------------------

// TestOIDC_IDTokenWithoutTheRequestedNonceIsRejected covers OIDC Core section
// 3.1.3.7 step 11 and finding F-18. Absence of the claim when one was requested
// is a hard failure: a nonce that can be omitted is a nonce an attacker removes.
// Type confusion is included because the claim arrives from JSON, where a
// number, a null, or an array is as easy to send as a string; each must be
// refused rather than coerced or read as absent.
func TestOIDC_IDTokenWithoutTheRequestedNonceIsRejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		claim   func(requested string) (map[string]interface{}, bool) // claims, includeNonce
		wantErr error
	}{
		{
			name:    "claim absent entirely",
			claim:   func(string) (map[string]interface{}, bool) { return map[string]interface{}{"sub": advVictimSub}, false },
			wantErr: ErrMissingNonce,
		},
		{
			name:    "raw claims map is nil",
			claim:   func(string) (map[string]interface{}, bool) { return nil, false },
			wantErr: ErrMissingNonce,
		},
		{
			name: "claim present but empty",
			claim: func(string) (map[string]interface{}, bool) {
				return map[string]interface{}{"nonce": ""}, false
			},
			wantErr: ErrMissingNonce,
		},
		{
			name: "claim present but null",
			claim: func(string) (map[string]interface{}, bool) {
				return map[string]interface{}{"nonce": nil}, false
			},
			wantErr: ErrMissingNonce,
		},
		{
			name: "claim present but a JSON number",
			claim: func(string) (map[string]interface{}, bool) {
				return map[string]interface{}{"nonce": float64(0)}, false
			},
			wantErr: ErrMissingNonce,
		},
		{
			name: "claim present but a JSON array holding the right value",
			claim: func(requested string) (map[string]interface{}, bool) {
				return map[string]interface{}{"nonce": []interface{}{requested}}, false
			},
			wantErr: ErrMissingNonce,
		},
		{
			name: "claim present but a JSON object holding the right value",
			claim: func(requested string) (map[string]interface{}, bool) {
				return map[string]interface{}{"nonce": map[string]interface{}{"value": requested}}, false
			},
			wantErr: ErrMissingNonce,
		},
		{
			name: "wrong value of the same length",
			claim: func(requested string) (map[string]interface{}, bool) {
				return map[string]interface{}{"nonce": advFlipLast(requested)}, false
			},
			wantErr: ErrNonceMismatch,
		},
		{
			name: "truncated by one byte, so a length short circuit would leak",
			claim: func(requested string) (map[string]interface{}, bool) {
				return map[string]interface{}{"nonce": requested[:len(requested)-1]}, false
			},
			wantErr: ErrNonceMismatch,
		},
		{
			name: "correct value with one byte appended",
			claim: func(requested string) (map[string]interface{}, bool) {
				return map[string]interface{}{"nonce": requested + "A"}, false
			},
			wantErr: ErrNonceMismatch,
		},
		{
			name: "a single leading byte, the shortest guess an attacker makes",
			claim: func(requested string) (map[string]interface{}, bool) {
				return map[string]interface{}{"nonce": requested[:1]}, false
			},
			wantErr: ErrNonceMismatch,
		},
		{
			name: "exactly the requested value",
			claim: func(requested string) (map[string]interface{}, bool) {
				return map[string]interface{}{"nonce": requested}, true
			},
			wantErr: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newAdvFlow(t, advOptions{claimsOnly: true})
			req := f.beginRaw(t, AuthURLOptions{})
			requested := f.nonceOf(req.State)
			if requested == "" {
				t.Fatalf("an OIDC flow stored no nonce; F-18 cannot be under test")
			}

			claims, _ := tc.claim(requested)
			f.idpAsserts(advHonestUserInfo(), claims)

			result, err := f.callback(req.State, req.Binding)
			if tc.wantErr != nil {
				advWantErr(t, err, tc.wantErr)
				advWantNoResult(t, result)
				return
			}
			if err != nil {
				t.Fatalf("the correct nonce must be accepted: %v", err)
			}
		})
	}
}

// TestOIDC_IDTokenFromAnotherFlowIsRejected is the replay F-18 exists for: an
// ID token captured from one authentication, presented into a second. Both
// flows are honest and both nonces are well formed; only the binding between
// the authorization request and the token distinguishes them.
func TestOIDC_IDTokenFromAnotherFlowIsRejected(t *testing.T) {
	t.Parallel()

	f := newAdvFlow(t, advOptions{claimsOnly: true})

	victim := f.beginRaw(t, AuthURLOptions{})
	attacker := f.beginRaw(t, AuthURLOptions{})

	victimNonce := f.nonceOf(victim.State)
	attackerNonce := f.nonceOf(attacker.State)
	if victimNonce == "" || attackerNonce == "" || victimNonce == attackerNonce {
		t.Fatalf("two flows must carry two distinct nonces, got %q and %q", victimNonce, attackerNonce)
	}

	// Replay the token minted for the attacker's flow into the victim's callback.
	f.idpAsserts(advHonestUserInfo(), map[string]interface{}{"nonce": attackerNonce})

	result, err := f.callback(victim.State, victim.Binding)
	advWantErr(t, err, ErrNonceMismatch)
	advWantNoResult(t, result)
}

// TestOIDC_NonceIsRequestedOnEveryOIDCAuthorization: a nonce that is verified
// but never sent is not a control. The authorization URL must carry it, it must
// be recorded server-side, and two flows must never share one.
func TestOIDC_NonceIsRequestedOnEveryOIDCAuthorization(t *testing.T) {
	t.Parallel()

	f := newAdvFlow(t, advOptions{claimsOnly: true})

	first := f.beginRaw(t, AuthURLOptions{})
	second := f.beginRaw(t, AuthURLOptions{})

	for _, req := range []*AuthorizationRequest{first, second} {
		parsed, err := url.Parse(req.URL)
		if err != nil {
			t.Fatalf("parse authorization URL: %v", err)
		}
		sent := parsed.Query().Get("nonce")
		if sent == "" {
			t.Fatalf("authorization URL carries no nonce: %s", req.URL)
		}
		if stored := f.nonceOf(req.State); stored != sent {
			t.Fatalf("nonce sent %q, nonce stored %q — a verifier that compares against a "+
				"different value than it sent verifies nothing", sent, stored)
		}
	}
	if f.nonceOf(first.State) == f.nonceOf(second.State) {
		t.Fatalf("two flows reused one nonce, which makes replay between them free")
	}
}

// TestOIDC_OAuth2OnlyFlowNeitherRequestsNorTrustsANonce: a provider that issues
// no ID token can return no nonce claim, so demanding one would break every
// such flow — but an attacker-supplied nonce claim on that path must not be
// mistaken for a passed check either.
func TestOIDC_OAuth2OnlyFlowNeitherRequestsNorTrustsANonce(t *testing.T) {
	t.Parallel()

	f := newAdvFlow(t, advOptions{oauth2Only: true, claimsOnly: true})
	req := f.beginRaw(t, AuthURLOptions{})

	parsed, err := url.Parse(req.URL)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}
	if got := parsed.Query().Get("nonce"); got != "" {
		t.Fatalf("an OAuth2-only authorization carried nonce=%q, which nothing can verify", got)
	}
	if stored := f.nonceOf(req.State); stored != "" {
		t.Fatalf("an OAuth2-only flow recorded nonce %q", stored)
	}

	// The provider volunteers a nonce anyway. It is not a control here and must
	// not be treated as one in either direction.
	f.idpAsserts(advHonestUserInfo(), map[string]interface{}{"nonce": advRandomValue(t, 32)})
	if _, err := f.callback(req.State, req.Binding); err != nil {
		t.Fatalf("an OAuth2-only callback must not fail on an unrequested nonce: %v", err)
	}
}

// --- F-17: PKCE -------------------------------------------------------------

// TestOIDC_AuthorizationURLCarriesAnS256ChallengeAndNeverTheVerifier covers
// RFC 7636 sections 4.2 and 4.3 and RFC 9700 section 2.1.1, which requires PKCE
// for every authorization-code client, confidential ones included. The
// challenge in the URL must be the SHA-256 of the stored verifier — recomputed
// here independently — and the verifier itself must never appear in a value
// that travels through the user agent, a proxy log, or a Referer header.
func TestOIDC_AuthorizationURLCarriesAnS256ChallengeAndNeverTheVerifier(t *testing.T) {
	t.Parallel()

	f := newAdvFlow(t, advOptions{claimsOnly: true})
	req := f.beginRaw(t, AuthURLOptions{})

	parsed, err := url.Parse(req.URL)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}
	query := parsed.Query()

	if got := query.Get("code_challenge_method"); got != "S256" {
		t.Fatalf("code_challenge_method = %q, want S256 — plain is a downgrade RFC 7636 "+
			"section 7.2 warns against", got)
	}
	verifier := f.verifierOf(t, req.State)
	challenge := query.Get("code_challenge")
	if challenge == "" {
		t.Fatalf("authorization URL carries no code_challenge: %s", req.URL)
	}
	if want := advS256Challenge(verifier); challenge != want {
		t.Fatalf("code_challenge = %q, want SHA-256 of the stored verifier %q", challenge, want)
	}
	if challenge == verifier {
		t.Fatalf("the challenge is the verifier in clear, which is the plain method under an S256 label")
	}
	if strings.Contains(req.URL, verifier) {
		t.Fatalf("the PKCE verifier appears in the authorization URL, so anyone who sees the "+
			"redirect can redeem an intercepted code: %s", req.URL)
	}

	// Two flows must not share a verifier, or one intercepted code is redeemable
	// with a challenge captured from another flow.
	second := f.beginRaw(t, AuthURLOptions{})
	if f.verifierOf(t, second.State) == verifier {
		t.Fatalf("two flows reused one PKCE verifier")
	}
}

// TestOIDC_TokenExchangeProvesPossessionOfThePKCEVerifier: the challenge is
// worthless unless the verifier is presented at the token endpoint. Without it,
// an authorization code intercepted in transit — a redirect through a hostile
// app, a logged URL, a Referer leak — is redeemable by whoever holds it
// (finding F-17).
func TestOIDC_TokenExchangeProvesPossessionOfThePKCEVerifier(t *testing.T) {
	t.Parallel()

	f := newAdvFlow(t, advOptions{claimsOnly: true})
	req := f.begin(t, AuthURLOptions{})
	verifier := f.verifierOf(t, req.State)

	if _, err := f.callback(req.State, req.Binding); err != nil {
		t.Fatalf("callback: %v", err)
	}

	form := f.tokens.lastForm(t)
	if got := form.Get("code_verifier"); got != verifier {
		t.Fatalf("token request sent code_verifier=%q, want the verifier stored for this flow %q",
			got, verifier)
	}
	if got := form.Get("grant_type"); got != "authorization_code" {
		t.Errorf("grant_type = %q, want authorization_code", got)
	}
	if got := form.Get("code"); got != advCode {
		t.Errorf("code = %q, want %q", got, advCode)
	}
}

// --- F-16: state binding and login CSRF -------------------------------------

// TestOIDC_LoginCSRFWithoutTheBrowserBindingIsRejected covers finding F-16,
// CWE-352. An attacker starts a flow, authenticates against their own account,
// and induces the victim to visit the resulting callback URL; the victim's
// browser is then signed in as the attacker, and everything they do afterwards
// is recorded in the attacker's account. A valid state proves only that some
// browser started a flow. Each row is a value an attacker can actually obtain,
// including the digest itself for an adversary with read access to the state
// store.
func TestOIDC_LoginCSRFWithoutTheBrowserBindingIsRejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		present func(t *testing.T, f *advFlow, req *AuthorizationRequest) string
		wantErr error
	}{
		{
			name:    "no cookie presented at all",
			present: func(*testing.T, *advFlow, *AuthorizationRequest) string { return "" },
			wantErr: ErrMissingBinding,
		},
		{
			name: "unrelated high-entropy guess",
			present: func(t *testing.T, _ *advFlow, _ *AuthorizationRequest) string {
				return advRandomValue(t, 32)
			},
			wantErr: ErrBindingMismatch,
		},
		{
			name: "one byte changed, same length",
			present: func(_ *testing.T, _ *advFlow, req *AuthorizationRequest) string {
				return advFlipLast(req.Binding)
			},
			wantErr: ErrBindingMismatch,
		},
		{
			name: "truncated by one byte",
			present: func(_ *testing.T, _ *advFlow, req *AuthorizationRequest) string {
				return req.Binding[:len(req.Binding)-1]
			},
			wantErr: ErrBindingMismatch,
		},
		{
			name: "correct value with a byte appended",
			present: func(_ *testing.T, _ *advFlow, req *AuthorizationRequest) string {
				return req.Binding + "A"
			},
			wantErr: ErrBindingMismatch,
		},
		{
			name: "the stored digest, replayed by a reader of the state store",
			present: func(t *testing.T, f *advFlow, req *AuthorizationRequest) string {
				return f.bindingDigestOf(t, req.State)
			},
			wantErr: ErrBindingMismatch,
		},
		{
			name: "a binding issued to a different flow in the same process",
			present: func(t *testing.T, f *advFlow, _ *AuthorizationRequest) string {
				other := f.beginRaw(t, AuthURLOptions{})
				return other.Binding
			},
			wantErr: ErrBindingMismatch,
		},
		{
			name:    "the binding this flow issued",
			present: func(_ *testing.T, _ *advFlow, req *AuthorizationRequest) string { return req.Binding },
			wantErr: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newAdvFlow(t, advOptions{claimsOnly: true})
			req := f.begin(t, AuthURLOptions{})

			result, err := f.callback(req.State, tc.present(t, f, req))
			if tc.wantErr != nil {
				advWantErr(t, err, tc.wantErr)
				advWantNoResult(t, result)
				// The binding is checked before the code is redeemed, so a
				// forged callback never spends the attacker's code either.
				advWantNoExchange(t, f.tokens)
				return
			}
			if err != nil {
				t.Fatalf("the issued binding must be accepted: %v", err)
			}
		})
	}
}

// TestOIDC_BoundFlowCannotBeCompletedThroughTheUnboundEntryPoint: an attacker
// who cannot produce the cookie will simply call the older signature that has
// no place to put one. Downgrading to HandleCallback must not strip the control
// the flow was started with.
func TestOIDC_BoundFlowCannotBeCompletedThroughTheUnboundEntryPoint(t *testing.T) {
	t.Parallel()

	f := newAdvFlow(t, advOptions{claimsOnly: true})
	req := f.begin(t, AuthURLOptions{})

	result, err := f.client.HandleCallback(context.Background(), req.State, advCode)
	advWantErr(t, err, ErrMissingBinding)
	advWantNoResult(t, result)
	advWantNoExchange(t, f.tokens)
}

// TestOIDC_BindingIsPersistedOnlyAsADigest: an adversary with read access to
// the state store (threat-model adversary 3 — a leaked backup, a snapshot, an
// injection elsewhere in the host application) must not recover a replayable
// value. Only the SHA-256 digest may be at rest.
func TestOIDC_BindingIsPersistedOnlyAsADigest(t *testing.T) {
	t.Parallel()

	f := newAdvFlow(t, advOptions{claimsOnly: true})
	req := f.beginRaw(t, AuthURLOptions{})

	rec := f.states.peek(req.State)
	if rec == nil {
		t.Fatalf("state was not stored")
	}
	for key, value := range rec.Metadata {
		if s, ok := value.(string); ok && s == req.Binding {
			t.Fatalf("state metadata key %q holds the binding value in clear", key)
		}
	}
	if got := f.bindingDigestOf(t, req.State); got == req.Binding {
		t.Fatalf("the stored binding equals the value handed to the browser")
	}
	if strings.Contains(req.URL, req.Binding) {
		t.Fatalf("the binding value travels in the authorization URL, where the provider and " +
			"every intermediary can read it")
	}
}

// --- state: replay, expiry, and the record's own contents -------------------

// TestOIDC_StateReplayIsRefused: OIDCStateStore.GetState is documented as
// one-time use, which is what makes the state parameter an anti-replay control
// (RFC 9700 section 2.1). A second callback carrying the same state — the shape
// of an authorization-code injection retried against a captured redirect — must
// find nothing.
func TestOIDC_StateReplayIsRefused(t *testing.T) {
	t.Parallel()

	f := newAdvFlow(t, advOptions{claimsOnly: true})
	req := f.begin(t, AuthURLOptions{})

	if _, err := f.callback(req.State, req.Binding); err != nil {
		t.Fatalf("first callback: %v", err)
	}
	if hits := f.tokens.hits(); hits != 1 {
		t.Fatalf("token endpoint hit %d time(s) for one callback, want 1", hits)
	}

	result, err := f.callback(req.State, req.Binding)
	advWantErr(t, err, ErrInvalidState)
	advWantNoResult(t, result)
	if hits := f.tokens.hits(); hits != 1 {
		t.Fatalf("a replayed state redeemed a code again: token endpoint hit %d time(s)", hits)
	}
}

// TestOIDC_ConcurrentStateReplayAdmitsExactlyOneCallback: a read-then-delete
// that is not atomic turns single-use into a race an attacker can win by firing
// the captured callback URL repeatedly. Run under -race against the shipped
// in-memory store.
func TestOIDC_ConcurrentStateReplayAdmitsExactlyOneCallback(t *testing.T) {
	t.Parallel()

	f := newAdvFlow(t, advOptions{claimsOnly: true})
	req := f.begin(t, AuthURLOptions{})

	const racers = 12
	var (
		wg        sync.WaitGroup
		successes atomic.Int64
		start     = make(chan struct{})
	)
	errs := make([]error, racers)
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := f.callback(req.State, req.Binding)
			errs[i] = err
			if err == nil {
				successes.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := successes.Load(); got != 1 {
		t.Fatalf("%d concurrent callbacks with one state succeeded, want exactly 1", got)
	}
	for i, err := range errs {
		if err != nil && !errors.Is(err, ErrInvalidState) {
			t.Errorf("racer %d: error = %v, want %v", i, err, ErrInvalidState)
		}
	}
	if hits := f.tokens.hits(); hits != 1 {
		t.Fatalf("the token endpoint was hit %d time(s), want 1 — a losing racer still spent a code", hits)
	}
}

// TestOIDC_ExpiredStateIsRefusedAndStillConsumed: an outstanding authorization
// request is a window, and a window that never closes is a permanent one. The
// record must also be consumed on the expired read, so a stale state cannot be
// probed repeatedly.
func TestOIDC_ExpiredStateIsRefusedAndStillConsumed(t *testing.T) {
	t.Parallel()

	f := newAdvFlow(t, advOptions{claimsOnly: true})
	const stale = "state-that-expired-while-the-user-made-tea"
	f.states.inject(t, stale, &storage.OIDCState{Provider: advProviderName}, -time.Minute)

	result, err := f.client.HandleCallback(context.Background(), stale, advCode)
	advWantErr(t, err, ErrInvalidState)
	advWantNoResult(t, result)
	advWantNoExchange(t, f.tokens)

	result, err = f.client.HandleCallback(context.Background(), stale, advCode)
	advWantErr(t, err, ErrInvalidState)
	advWantNoResult(t, result)
	advWantNoExchange(t, f.tokens)

	// And the window a live flow gets is bounded.
	req := f.beginRaw(t, AuthURLOptions{})
	if ttl := f.states.ttlOf(req.State); ttl <= 0 || ttl > DefaultStateTTL {
		t.Fatalf("state TTL = %v, want a positive value no greater than %v", ttl, DefaultStateTTL)
	}
}

// TestOIDC_UnknownProviderInTheStateRecordIsRefusedBeforeAnyExchange: the
// provider is read from the state record, which an attacker may have planted or
// which may have been written by another version of the application. An
// unresolvable or unusable connection must stop the callback before the code is
// redeemed against anything.
func TestOIDC_UnknownProviderInTheStateRecordIsRefusedBeforeAnyExchange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		provider string
		wantErr  error
	}{
		{name: "provider that was never registered", provider: "attacker-controlled-idp", wantErr: ErrProviderNotFound},
		{name: "empty provider name", provider: "", wantErr: ErrProviderNotFound},
		{name: "name differing only in case", provider: strings.ToUpper(advProviderName), wantErr: ErrProviderNotFound},
		{name: "name with trailing whitespace", provider: advProviderName + " ", wantErr: ErrProviderNotFound},
		{name: "registered but supplying no OAuth2 config", provider: "misconfigured", wantErr: ErrProviderMisconfigured},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newAdvFlow(t, advOptions{claimsOnly: true, withBrokenProvider: true})
			state := "planted-state-" + advRandomValue(t, 8)
			f.states.inject(t, state, &storage.OIDCState{Provider: tc.provider}, DefaultStateTTL)

			result, err := f.client.HandleCallback(context.Background(), state, advCode)
			advWantErr(t, err, tc.wantErr)
			advWantNoResult(t, result)
			advWantNoExchange(t, f.tokens)
		})
	}
}

// TestOIDC_CorruptStateMetadataIsNeverReadAsAnAbsentControl: the PKCE verifier
// and the binding digest live in the state record's metadata. A value of the
// wrong type means the record was truncated, rewritten, or produced by another
// writer, and reading that as "no value present" silently removes the control —
// which is exactly what an attacker with any influence over the record would
// choose. Each row is a shape a JSON round trip or a foreign writer produces.
func TestOIDC_CorruptStateMetadataIsNeverReadAsAnAbsentControl(t *testing.T) {
	t.Parallel()

	corruptions := []struct {
		name  string
		value interface{}
	}{
		{name: "JSON number", value: float64(1)},
		{name: "JSON null", value: nil},
		{name: "JSON array", value: []interface{}{"value"}},
		{name: "JSON object", value: map[string]interface{}{"v": "value"}},
		{name: "boolean", value: true},
		{name: "byte slice", value: []byte("value")},
	}
	keys := []struct {
		name string
		key  string
	}{
		{name: "binding digest", key: StateMetadataKeyBinding},
		{name: "PKCE verifier", key: StateMetadataKeyPKCEVerifier},
	}

	for _, k := range keys {
		for _, c := range corruptions {
			t.Run(k.name+"/"+c.name, func(t *testing.T) {
				t.Parallel()

				f := newAdvFlow(t, advOptions{claimsOnly: true})
				req := f.begin(t, AuthURLOptions{})
				key, value := k.key, c.value
				f.states.onRead(func(rec *storage.OIDCState) {
					if rec.Metadata == nil {
						rec.Metadata = map[string]interface{}{}
					}
					rec.Metadata[key] = value
				})

				result, err := f.callback(req.State, req.Binding)
				advWantErr(t, err, ErrCorruptState)
				advWantNoResult(t, result)
				advWantNoExchange(t, f.tokens)
			})
		}
	}
}

// --- state metadata: the library's own keys are not the caller's ------------

// TestOIDC_CallerCannotWriteOrReadTheLibrarysStateMetadata: a caller that could
// write under the reserved prefix could pin the PKCE verifier to a value it
// knows, or install a binding digest for a value it holds, which turns both
// controls into decoration. A caller that could read them back would put the
// verifier into a log or a template.
func TestOIDC_CallerCannotWriteOrReadTheLibrarysStateMetadata(t *testing.T) {
	t.Parallel()

	t.Run("reserved keys are refused at authorization time", func(t *testing.T) {
		t.Parallel()

		reserved := []string{
			StateMetadataKeyPKCEVerifier,
			StateMetadataKeyBinding,
			StateMetadataPrefix,
			StateMetadataPrefix + "anything",
		}
		for _, key := range reserved {
			f := newAdvFlow(t, advOptions{claimsOnly: true})
			_, err := f.client.GetAuthorizationURLWithBinding(context.Background(), AuthURLOptions{
				Provider: advProviderName,
				Metadata: map[string]interface{}{key: "attacker-chosen"},
			})
			advWantErr(t, err, ErrReservedMetadataKey)
			if got := f.states.count(); got != 0 {
				t.Fatalf("key %q: a refused authorization stored %d state record(s)", key, got)
			}
		}
	})

	t.Run("a key that merely contains the prefix is the caller's own", func(t *testing.T) {
		t.Parallel()

		f := newAdvFlow(t, advOptions{claimsOnly: true})
		caller := map[string]interface{}{
			"not-go-auth/pkce_verifier": "mine",
			"tenant":                    "acme-corp",
		}
		req := f.beginRaw(t, AuthURLOptions{Metadata: caller})
		f.idpAsserts(advHonestUserInfo(), map[string]interface{}{"nonce": f.nonceOf(req.State)})

		result, err := f.callback(req.State, req.Binding)
		if err != nil {
			t.Fatalf("callback: %v", err)
		}
		if got := result.Metadata["tenant"]; got != "acme-corp" {
			t.Errorf("caller metadata tenant = %v, want acme-corp", got)
		}
		if got := result.Metadata["not-go-auth/pkce_verifier"]; got != "mine" {
			t.Errorf("a key that only contains the prefix was stripped: %v", got)
		}
		if _, mutated := caller[StateMetadataKeyPKCEVerifier]; mutated {
			t.Errorf("the library wrote its own key into the caller's map")
		}
	})

	t.Run("the verifier and the digest never reach the caller", func(t *testing.T) {
		t.Parallel()

		f := newAdvFlow(t, advOptions{claimsOnly: true})
		req := f.begin(t, AuthURLOptions{Metadata: map[string]interface{}{"tenant": "acme-corp"}})
		verifier := f.verifierOf(t, req.State)
		digestValue := f.bindingDigestOf(t, req.State)

		result, err := f.callback(req.State, req.Binding)
		if err != nil {
			t.Fatalf("callback: %v", err)
		}
		for key, value := range result.Metadata {
			if strings.HasPrefix(key, StateMetadataPrefix) {
				t.Errorf("CallbackResult.Metadata leaked reserved key %q", key)
			}
			if s, ok := value.(string); ok && (s == verifier || s == digestValue) {
				t.Errorf("CallbackResult.Metadata key %q leaked a library secret", key)
			}
		}
	})
}

// --- F-21: the IdP's claims are not the application's metadata --------------

// TestOIDC_RawClaimsAreNotCopiedIntoUserMetadata covers finding F-21, CWE-200.
// The pre-fix code stored the entire raw claim set under Metadata["raw_claims"],
// and the JWT package then copied user metadata wholesale into the token it
// handed the browser: every group membership, internal identifier and directory
// attribute the IdP released, base64-decodable by anyone who saw the token.
// Only the subject — the value a later assertion is checked against — is the
// library's to keep.
func TestOIDC_RawClaimsAreNotCopiedIntoUserMetadata(t *testing.T) {
	t.Parallel()

	fatClaims := map[string]interface{}{
		"sub":                             advVictimSub,
		"email":                           advVictimEmail,
		"groups":                          []interface{}{"domain-admins", "finance"},
		"roles":                           []interface{}{"superuser"},
		"https://claims.example/employee": "E-000123",
		"phone_number":                    "+15550100",
		"raw_claims":                      map[string]interface{}{"nested": "everything"},
		"padding":                         strings.Repeat("x", 4096),
	}

	tests := []struct {
		name      string
		allowlist []string
		wantKeys  map[string]bool
	}{
		{
			name:      "no allow-list keeps only the subject",
			allowlist: nil,
			wantKeys:  map[string]bool{UserMetadataKeyProviderSubject: true},
		},
		{
			name:      "an allow-list keeps only what it names",
			allowlist: []string{"groups"},
			wantKeys:  map[string]bool{UserMetadataKeyProviderSubject: true, "groups": true},
		},
		{
			name:      "an allow-listed claim that is absent adds nothing",
			allowlist: []string{"groups", "not_asserted"},
			wantKeys:  map[string]bool{UserMetadataKeyProviderSubject: true, "groups": true},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newAdvFlow(t, advOptions{allowlist: tc.allowlist})
			req := f.beginRaw(t, AuthURLOptions{})
			claims := make(map[string]interface{}, len(fatClaims)+1)
			for k, v := range fatClaims {
				claims[k] = v
			}
			claims["nonce"] = f.nonceOf(req.State)
			f.idpAsserts(advHonestUserInfo(), claims)

			result, err := f.callback(req.State, req.Binding)
			if err != nil {
				t.Fatalf("callback: %v", err)
			}
			if result.User == nil {
				t.Fatalf("no user was created")
			}
			if !result.IsNewUser {
				t.Fatalf("IsNewUser = false for a freshly provisioned account")
			}

			got := result.User.Metadata
			if len(got) != len(tc.wantKeys) {
				t.Fatalf("user metadata = %#v, want exactly the keys %v", got, tc.wantKeys)
			}
			for key := range got {
				if !tc.wantKeys[key] {
					t.Errorf("user metadata carries un-allow-listed claim %q", key)
				}
			}
			if _, leaked := got["raw_claims"]; leaked {
				t.Errorf("the whole raw claim set was stored under raw_claims — finding F-21")
			}
			sub, ok := got[UserMetadataKeyProviderSubject].(string)
			if !ok || sub != advVictimSub {
				t.Errorf("provider_sub = %v, want the asserted subject %q", got[UserMetadataKeyProviderSubject], advVictimSub)
			}
		})
	}
}

// TestOIDC_AllowListedClaimCannotDisplaceTheRecordedSubject: an application
// that allow-lists a claim named provider_sub, against a provider that asserts
// one, would otherwise let the IdP choose the value every future adoption check
// compares against — an nOAuth takeover deferred by one sign-in.
func TestOIDC_AllowListedClaimCannotDisplaceTheRecordedSubject(t *testing.T) {
	t.Parallel()

	f := newAdvFlow(t, advOptions{allowlist: []string{UserMetadataKeyProviderSubject, "groups"}})
	req := f.beginRaw(t, AuthURLOptions{})
	f.idpAsserts(advHonestUserInfo(), map[string]interface{}{
		"nonce":                        f.nonceOf(req.State),
		UserMetadataKeyProviderSubject: "subject-the-attacker-picked",
		"groups":                       []interface{}{"admins"},
	})

	result, err := f.callback(req.State, req.Binding)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	sub, ok := result.User.Metadata[UserMetadataKeyProviderSubject].(string)
	if !ok || sub != advVictimSub {
		t.Fatalf("recorded provider_sub = %q, want the verified subject %q — an allow-listed "+
			"claim overwrote the adoption key", sub, advVictimSub)
	}
}

// --- authorization URL construction -----------------------------------------

// TestOIDC_ScopeOverrideKeepsTheEndpointStateAndPKCEIntact guards the
// regression where the authorization URL was constructed twice: once before the
// scope override and once after. The second build minted its own state and its
// own PKCE challenge, so the value in the URL the user followed was not the
// value in the state store, and both controls were dead on arrival. Overriding
// the scopes must also not mutate the provider's shared *oauth2.Config, which
// every concurrent flow reads.
func TestOIDC_ScopeOverrideKeepsTheEndpointStateAndPKCEIntact(t *testing.T) {
	t.Parallel()

	entry := []struct {
		name  string
		build func(t *testing.T, f *advFlow, opts AuthURLOptions) string
	}{
		{
			name: "GetAuthorizationURL",
			build: func(t *testing.T, f *advFlow, opts AuthURLOptions) string {
				t.Helper()
				got, err := f.client.GetAuthorizationURL(context.Background(), opts)
				if err != nil {
					t.Fatalf("GetAuthorizationURL: %v", err)
				}
				return got
			},
		},
		{
			name: "GetAuthorizationURLWithBinding",
			build: func(t *testing.T, f *advFlow, opts AuthURLOptions) string {
				t.Helper()
				req, err := f.client.GetAuthorizationURLWithBinding(context.Background(), opts)
				if err != nil {
					t.Fatalf("GetAuthorizationURLWithBinding: %v", err)
				}
				return req.URL
			},
		},
	}

	for _, e := range entry {
		t.Run(e.name, func(t *testing.T) {
			t.Parallel()

			f := newAdvFlow(t, advOptions{claimsOnly: true})
			defaults := append([]string(nil), f.provider.cfg.Scopes...)
			overridden := []string{"openid", "offline_access", "groups"}

			raw := e.build(t, f, AuthURLOptions{
				Provider: advProviderName,
				Scopes:   overridden,
			})

			parsed, err := url.Parse(raw)
			if err != nil {
				t.Fatalf("parse authorization URL: %v", err)
			}
			query := parsed.Query()

			// The endpoint config survives the override.
			wantPrefix := f.provider.cfg.Endpoint.AuthURL
			if !strings.HasPrefix(raw, wantPrefix) {
				t.Fatalf("authorization URL %q does not target the provider's endpoint %q", raw, wantPrefix)
			}
			if got := query.Get("client_id"); got != f.provider.cfg.ClientID {
				t.Errorf("client_id = %q, want %q", got, f.provider.cfg.ClientID)
			}
			if got := query.Get("redirect_uri"); got != f.provider.cfg.RedirectURL {
				t.Errorf("redirect_uri = %q, want %q", got, f.provider.cfg.RedirectURL)
			}
			if got := query.Get("scope"); got != strings.Join(overridden, " ") {
				t.Errorf("scope = %q, want %q", got, strings.Join(overridden, " "))
			}

			// Exactly one state was minted, and it is the one in the URL.
			if got := f.states.count(); got != 1 {
				t.Fatalf("%d state records were stored for one authorization, want 1 — the URL "+
					"was built more than once", got)
			}
			state := query.Get("state")
			if state == "" {
				t.Fatalf("authorization URL carries no state")
			}
			rec := f.states.peek(state)
			if rec == nil {
				t.Fatalf("the state in the URL (%q) is not the state that was stored", state)
			}
			if rec.Provider != advProviderName {
				t.Errorf("stored provider = %q, want %q", rec.Provider, advProviderName)
			}

			// And the PKCE challenge in the URL is the one for the stored verifier.
			verifier, ok := rec.Metadata[StateMetadataKeyPKCEVerifier].(string)
			if !ok || verifier == "" {
				t.Fatalf("stored state carries no PKCE verifier: %#v", rec.Metadata)
			}
			if got, want := query.Get("code_challenge"), advS256Challenge(verifier); got != want {
				t.Fatalf("code_challenge = %q, want the challenge for the stored verifier %q", got, want)
			}
			if got := query.Get("code_challenge_method"); got != "S256" {
				t.Errorf("code_challenge_method = %q, want S256", got)
			}
			if rec.Nonce != "" && query.Get("nonce") != rec.Nonce {
				t.Errorf("nonce in URL = %q, want the stored %q", query.Get("nonce"), rec.Nonce)
			}

			// The provider's own configuration is shared by every concurrent
			// flow and must come back unchanged.
			if strings.Join(f.provider.cfg.Scopes, " ") != strings.Join(defaults, " ") {
				t.Fatalf("the scope override mutated the provider's shared config: %v", f.provider.cfg.Scopes)
			}
		})
	}
}

// TestOIDC_EmptyStateOrCodeNeverReachesTheStateStore: a callback with a missing
// parameter is refused on argument shape alone. Passing it through to the store
// turns the store into an oracle for whether a state value exists, and hands an
// unauthenticated caller a free lookup per request.
func TestOIDC_EmptyStateOrCodeNeverReachesTheStateStore(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, state, code string }{
		{name: "both empty", state: "", code: ""},
		{name: "empty state", state: "", code: advCode},
		{name: "empty code", state: "some-state", code: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newAdvFlow(t, advOptions{claimsOnly: true})
			result, err := f.client.HandleCallbackWithBinding(context.Background(), tc.state, tc.code, "binding")
			advWantErr(t, err, ErrInvalidState)
			advWantNoResult(t, result)
			if got := f.states.gets.Load(); got != 0 {
				t.Fatalf("the state store was consulted %d time(s) for a malformed callback", got)
			}
			advWantNoExchange(t, f.tokens)
		})
	}
}

// TestOIDC_MixUpBetweenTwoRegisteredConnections covers the identity-provider
// mix-up of RFC 9700 section 4.4. Two connections are registered; the callback
// carries no provider parameter of its own, so the code minted for one tenant's
// IdP can only ever be redeemed at the endpoint of the connection recorded in
// the state record. If the connection were taken from anywhere the attacker can
// influence, a code issued by a hostile IdP would be redeemed at an honest one.
func TestOIDC_MixUpBetweenTwoRegisteredConnections(t *testing.T) {
	t.Parallel()

	f := newAdvFlow(t, advOptions{claimsOnly: true, withForeignProvider: true})
	req := f.begin(t, AuthURLOptions{Provider: advProviderName})

	result, err := f.callback(req.State, req.Binding)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if got := f.tokens.hits(); got != 1 {
		t.Fatalf("the flow's own token endpoint was hit %d time(s), want 1", got)
	}
	if got := f.foreignT.hits(); got != 0 {
		t.Fatalf("the other connection's token endpoint was hit %d time(s), want 0", got)
	}
	if result.UserInfo.Provider != advProviderName {
		t.Fatalf("UserInfo.Provider = %q, want %q", result.UserInfo.Provider, advProviderName)
	}
	if f.provider.calls.Load() != 1 || f.foreign.calls.Load() != 0 {
		t.Fatalf("assertion was extracted by the wrong connection: %d vs %d",
			f.provider.calls.Load(), f.foreign.calls.Load())
	}
}

// TestOIDC_ProviderFailureIsNotReportedAsAnIdentity: a provider that returns no
// user info, or an error, must abort the callback. Reporting a zero-valued
// UserInfo would present an empty subject and an empty email to the application
// as if they had been verified.
func TestOIDC_ProviderFailureIsNotReportedAsAnIdentity(t *testing.T) {
	t.Parallel()

	t.Run("nil user info with a nil error", func(t *testing.T) {
		t.Parallel()

		f := newAdvFlow(t, advOptions{claimsOnly: true})
		req := f.beginRaw(t, AuthURLOptions{})
		//nolint:nilnil // a provider reporting success with no assertion is the contract violation under test.
		f.provider.setExtract(func(context.Context, *oauth2.Token) (*UserInfo, error) {
			return nil, nil
		})

		result, err := f.callback(req.State, req.Binding)
		advWantErr(t, err, ErrUserInfoFailed)
		advWantNoResult(t, result)
	})

	t.Run("extraction error is surfaced, not swallowed", func(t *testing.T) {
		t.Parallel()

		sentinel := fmt.Errorf("adversarial: id token signature invalid")
		f := newAdvFlow(t, advOptions{claimsOnly: true})
		req := f.beginRaw(t, AuthURLOptions{})
		f.provider.setExtract(func(context.Context, *oauth2.Token) (*UserInfo, error) {
			return nil, sentinel
		})

		result, err := f.callback(req.State, req.Binding)
		advWantErr(t, err, ErrUserInfoFailed)
		advWantErr(t, err, sentinel)
		advWantNoResult(t, result)
	})
}

// --- the state store is not a black box -------------------------------------
//
// The findings above are all enforced against a store that keeps every field it
// is given. A store is application code, and the one thing a library cannot
// make it do is persist a column its author did not know to add. The tests in
// this section run the whole flow against backends that keep only part of the
// record, because a control that disappears with the field it lived in is a
// control that was never there.

// advShapedStateStore is a state store with a column list. strip removes, on
// the way in, exactly the fields this backend has nowhere to put; everything
// else round-trips through the real in-memory store.
type advShapedStateStore struct {
	inner storage.OIDCStateStore
	strip func(*storage.OIDCState)
}

var _ storage.OIDCStateStore = (*advShapedStateStore)(nil)

func newAdvShapedStateStore(strip func(*storage.OIDCState)) *advShapedStateStore {
	return &advShapedStateStore{inner: storage.NewInMemoryOIDCStateStore(), strip: strip}
}

func (s *advShapedStateStore) StoreState(ctx context.Context, state string, data *storage.OIDCState, ttl time.Duration) error {
	kept := advCloneState(data)
	s.strip(kept)
	return s.inner.StoreState(ctx, state, kept, ttl)
}

func (s *advShapedStateStore) GetState(ctx context.Context, state string) (*storage.OIDCState, error) {
	return s.inner.GetState(ctx, state)
}

func (s *advShapedStateStore) DeleteState(ctx context.Context, state string) error {
	return s.inner.DeleteState(ctx, state)
}

// advDropStateMetadata models the store a v1.2 implementor writes from the
// documentation alone: one column per documented field of storage.OIDCState and
// nowhere to put an opaque map. This is the store that passed the shipped
// conformance suite while the binding check never fired and the token exchange
// went out with no PKCE at all.
func advDropStateMetadata(rec *storage.OIDCState) { rec.Metadata = nil }

// advDropTypedStateFields models the store a v1.1.1 implementor wrote: it
// predates CodeVerifier and BindingHash, so those columns do not exist, and it
// persists the metadata map because that is where the library kept its controls
// at the time.
func advDropTypedStateFields(rec *storage.OIDCState) {
	rec.CodeVerifier = ""
	rec.BindingHash = ""
	rec.Nonce = ""
}

// advDropControl removes one control from BOTH places it is written, which is
// what a store that recognizes neither location does.
func advDropControl(typed func(*storage.OIDCState), key string) func(*storage.OIDCState) {
	return func(rec *storage.OIDCState) {
		typed(rec)
		delete(rec.Metadata, key)
	}
}

// TestOIDC_PartialStoreStillEnforcesEveryControl: each control is written to a
// typed field and to a mirrored metadata key, so a store that keeps either one
// keeps the control. Reverting one of the two writes makes the matching half of
// this test authenticate a callback that proves nothing.
func TestOIDC_PartialStoreStillEnforcesEveryControl(t *testing.T) {
	t.Parallel()

	shapes := []struct {
		name  string
		strip func(*storage.OIDCState)
	}{
		{name: "typed columns only, no metadata", strip: advDropStateMetadata},
		{name: "metadata only, no typed columns", strip: advDropTypedStateFields},
	}

	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			t.Parallel()

			newFlow := func(t *testing.T) *advFlow {
				t.Helper()
				return newAdvFlow(t, advOptions{
					claimsOnly: true,
					stateStore: newAdvShapedStateStore(shape.strip),
				})
			}

			t.Run("the browser binding is still required", func(t *testing.T) {
				t.Parallel()

				f := newFlow(t)
				req := f.begin(t, AuthURLOptions{})

				result, err := f.client.HandleCallback(context.Background(), req.State, advCode)
				advWantErr(t, err, ErrMissingBinding)
				advWantNoResult(t, result)
				advWantNoExchange(t, f.tokens)
			})

			t.Run("a forged browser binding is still refused", func(t *testing.T) {
				t.Parallel()

				f := newFlow(t)
				req := f.begin(t, AuthURLOptions{})

				result, err := f.callback(req.State, advFlipLast(req.Binding))
				advWantErr(t, err, ErrBindingMismatch)
				advWantNoResult(t, result)
				advWantNoExchange(t, f.tokens)
			})

			t.Run("a replayed nonce is still refused", func(t *testing.T) {
				t.Parallel()

				f := newFlow(t)
				req := f.begin(t, AuthURLOptions{})
				f.idpAsserts(advHonestUserInfo(), map[string]interface{}{
					"nonce": "nonce-minted-for-a-different-authentication",
				})

				result, err := f.callback(req.State, req.Binding)
				advWantErr(t, err, ErrNonceMismatch)
				advWantNoResult(t, result)
			})

			t.Run("the exchange still proves possession of the PKCE verifier", func(t *testing.T) {
				t.Parallel()

				f := newFlow(t)
				req := f.begin(t, AuthURLOptions{})
				verifier := f.verifierOf(t, req.State)

				if _, err := f.callback(req.State, req.Binding); err != nil {
					t.Fatalf("an honest callback must complete: %v", err)
				}
				form := f.tokens.lastForm(t)
				if got := form.Get("code_verifier"); got != verifier {
					t.Fatalf("token request code_verifier = %q, want the verifier for this flow (F-17)", got)
				}
			})
		})
	}
}

// TestOIDC_StoreThatDropsAControlFailsClosed: when NEITHER location survives,
// there is nothing left to fall back on. The callback must refuse rather than
// carry on with the control silently absent — the difference between a store
// bug that stops sign-in and a store bug that removes PKCE from every exchange.
func TestOIDC_StoreThatDropsAControlFailsClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		strip func(*storage.OIDCState)
	}{
		{
			name: "PKCE verifier",
			strip: advDropControl(func(rec *storage.OIDCState) { rec.CodeVerifier = "" },
				StateMetadataKeyPKCEVerifier),
		},
		{
			name: "browser-binding marker",
			strip: advDropControl(func(rec *storage.OIDCState) { rec.BindingHash = "" },
				StateMetadataKeyBinding),
		},
		{
			name: "nonce of an OIDC flow",
			strip: advDropControl(func(rec *storage.OIDCState) { rec.Nonce = "" },
				StateMetadataKeyNonce),
		},
		{
			name: "every control at once",
			strip: func(rec *storage.OIDCState) {
				advDropTypedStateFields(rec)
				advDropStateMetadata(rec)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newAdvFlow(t, advOptions{
				claimsOnly: true,
				stateStore: newAdvShapedStateStore(tc.strip),
			})
			req := f.begin(t, AuthURLOptions{})

			result, err := f.callback(req.State, req.Binding)
			advWantErr(t, err, ErrStateControlMissing)
			advWantNoResult(t, result)
			advWantNoExchange(t, f.tokens)
		})
	}
}

// TestOIDC_StateRecordFromAnEarlierReleaseIsRefusedNotDowngraded: a record
// written before any of these controls existed carries none of them, and is
// indistinguishable from a record a store stripped. Completing it would mean an
// attacker who can plant a bare record gets a flow with no PKCE, no binding and
// no nonce; refusing it costs at most one sign-in per caller mid-flow across a
// deploy, inside the ten-minute state TTL.
func TestOIDC_StateRecordFromAnEarlierReleaseIsRefusedNotDowngraded(t *testing.T) {
	t.Parallel()

	f := newAdvFlow(t, advOptions{claimsOnly: true})
	planted := "state-written-by-an-earlier-release-" + advRandomValue(t, 8)
	f.states.inject(t, planted, &storage.OIDCState{
		Provider:    advProviderName,
		RedirectURL: "https://app.example/home",
	}, DefaultStateTTL)

	result, err := f.client.HandleCallback(context.Background(), planted, advCode)
	advWantErr(t, err, ErrStateControlMissing)
	advWantNoResult(t, result)
	advWantNoExchange(t, f.tokens)
}

// TestOIDC_TypedControlAndItsMirrorMustAgree: the two copies are written from
// one variable in one call, so a disagreement cannot be something this package
// produced. Preferring either half would let a writer who can reach one
// location choose the verifier or the binding digest the callback uses.
func TestOIDC_TypedControlAndItsMirrorMustAgree(t *testing.T) {
	t.Parallel()

	keys := []string{StateMetadataKeyPKCEVerifier, StateMetadataKeyBinding, StateMetadataKeyNonce}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			t.Parallel()

			f := newAdvFlow(t, advOptions{claimsOnly: true})
			req := f.begin(t, AuthURLOptions{})
			rewritten := key
			f.states.onRead(func(rec *storage.OIDCState) {
				rec.Metadata[rewritten] = "value-written-by-something-else"
			})

			result, err := f.callback(req.State, req.Binding)
			advWantErr(t, err, ErrCorruptState)
			advWantNoResult(t, result)
			advWantNoExchange(t, f.tokens)
		})
	}
}

// --- F-01: provisioning is a decision the application owns -------------------

// TestOIDC_AccountCreationRequiresAnExplicitPolicy: every control in this
// package can pass and still leave one question open — whether the connection
// that authenticated is entitled to the address it asserted. A tenant-configured
// IdP asserting cfo@victim-corp.example with email_verified true satisfies every
// other check; provisioning on that alone squats the address, and the real owner
// meets ErrAccountLinkRequired forever after.
func TestOIDC_AccountCreationRequiresAnExplicitPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		opts     advOptions
		wantErr  error
		wantUser bool
	}{
		{
			name:    "no policy configured refuses",
			opts:    advOptions{noCreatePolicy: true},
			wantErr: ErrAccountCreationRefused,
		},
		{
			name: "policy returning false refuses",
			opts: advOptions{createPolicy: func(context.Context, *UserInfo) (bool, error) {
				return false, nil
			}},
			wantErr: ErrAccountCreationRefused,
		},
		{
			name: "policy returning an error aborts",
			opts: advOptions{createPolicy: func(context.Context, *UserInfo) (bool, error) {
				return false, errAdvLinkPolicyExploded
			}},
			wantErr: errAdvLinkPolicyExploded,
		},
		{
			name: "policy erroring while also returning true still aborts",
			opts: advOptions{createPolicy: func(context.Context, *UserInfo) (bool, error) {
				return true, errAdvLinkPolicyExploded
			}},
			wantErr: errAdvLinkPolicyExploded,
		},
		{
			name:     "AllowAccountCreation restores the old behavior in one line",
			opts:     advOptions{createPolicy: AllowAccountCreation},
			wantUser: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newAdvFlow(t, tc.opts)
			req := f.begin(t, AuthURLOptions{})

			result, err := f.callback(req.State, req.Binding)
			if !tc.wantUser {
				advWantErr(t, err, tc.wantErr)
				advWantNoResult(t, result)
				if got := f.users.created(); got != 0 {
					t.Fatalf("a refused provisioning created %d account(s), want 0", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("an authorized provisioning must succeed: %v", err)
			}
			if result.User == nil || !result.IsNewUser {
				t.Fatalf("result = %#v, want a newly created account", result)
			}
			if got := f.users.created(); got != 1 {
				t.Fatalf("created %d account(s), want 1", got)
			}
		})
	}
}

// TestOIDC_CreatePolicySeesTheVerifiedAssertionAndOnlyWhenDeciding: a policy
// handed an assertion stripped of its subject cannot tell one identity from
// another, and a policy consulted when nothing needs deciding trains the
// application to approve.
func TestOIDC_CreatePolicySeesTheVerifiedAssertionAndOnlyWhenDeciding(t *testing.T) {
	t.Parallel()

	var (
		mu    sync.Mutex
		seen  []*UserInfo
		calls atomic.Int64
	)
	policy := func(_ context.Context, info *UserInfo) (bool, error) {
		calls.Add(1)
		mu.Lock()
		seen = append(seen, info)
		mu.Unlock()
		return true, nil
	}

	f := newAdvFlow(t, advOptions{createPolicy: policy})
	req := f.begin(t, AuthURLOptions{})
	if _, err := f.callback(req.State, req.Binding); err != nil {
		t.Fatalf("callback: %v", err)
	}

	if got := calls.Load(); got != 1 {
		t.Fatalf("CreatePolicy called %d time(s), want exactly 1", got)
	}
	mu.Lock()
	got := seen[0]
	mu.Unlock()
	switch {
	case got == nil:
		t.Fatal("CreatePolicy saw no assertion")
	case got.Subject != advVictimSub:
		t.Errorf("CreatePolicy saw subject %q, want %q", got.Subject, advVictimSub)
	case got.Email != advVictimEmail:
		t.Errorf("CreatePolicy saw email %q, want %q", got.Email, advVictimEmail)
	case got.Provider != advProviderName:
		t.Errorf("CreatePolicy saw provider %q, want the registered connection %q", got.Provider, advProviderName)
	case !got.EmailVerified:
		t.Error("CreatePolicy was consulted for an assertion that had not passed the email check")
	}

	// A second flow that resolves to the account just created decides nothing,
	// so the policy must not be consulted again.
	before := calls.Load()
	req2 := f.begin(t, AuthURLOptions{})
	if _, err := f.callback(req2.State, req2.Binding); err != nil {
		t.Fatalf("returning sign-in: %v", err)
	}
	if after := calls.Load(); after != before {
		t.Fatalf("CreatePolicy was consulted %d extra time(s) for an existing account", after-before)
	}
}

// TestOIDC_CreatedAccountRecordsTheSubjectInBothPlaces: the subject is what
// every later assertion is checked against. Written to only one of the two
// locations, an account created here becomes unmatchable — and therefore
// permanently locked out — on any store that keeps the other one.
func TestOIDC_CreatedAccountRecordsTheSubjectInBothPlaces(t *testing.T) {
	t.Parallel()

	f := newAdvFlow(t, advOptions{})
	req := f.begin(t, AuthURLOptions{})

	result, err := f.callback(req.State, req.Binding)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if result.User.ProviderSubject != advVictimSub {
		t.Errorf("User.ProviderSubject = %q, want the asserted subject %q",
			result.User.ProviderSubject, advVictimSub)
	}

	stored, err := f.users.GetUserByEmail(context.Background(), advVictimEmail)
	if err != nil {
		t.Fatalf("read the account back: %v", err)
	}
	if stored.ProviderSubject != advVictimSub {
		t.Errorf("persisted ProviderSubject = %q, want %q", stored.ProviderSubject, advVictimSub)
	}
	if got := stored.Metadata[UserMetadataKeyProviderSubject]; got != advVictimSub {
		t.Errorf("persisted metadata subject = %v, want %q", got, advVictimSub)
	}
}

// TestOIDC_AccountPredatingSubjectRecordingIsPinnedOnFirstSignIn: no account any
// earlier release created carries a subject anywhere, so the F-01 check can
// never match one and its owner is refused on every sign-in with no way to clear
// it. The account was provisioned by this same registered connection, so it is
// adopted once and pinned — and the pin is what makes it a one-time step rather
// than a standing weakness.
func TestOIDC_AccountPredatingSubjectRecordingIsPinnedOnFirstSignIn(t *testing.T) {
	t.Parallel()

	f := newAdvFlow(t, advOptions{})
	f.users.seed(t, &storage.User{
		ID: "legacy", Email: advVictimEmail, EmailVerified: true, Provider: advProviderName,
	})

	req := f.begin(t, AuthURLOptions{})
	result, err := f.callback(req.State, req.Binding)
	if err != nil {
		t.Fatalf("an account created before subjects were recorded must not be locked out: %v", err)
	}
	if result.User == nil || result.User.ID != "legacy" {
		t.Fatalf("adopted user = %#v, want the existing account", result.User)
	}
	if result.IsNewUser {
		t.Error("IsNewUser = true for an adopted account")
	}
	if got := f.users.created(); got != 0 {
		t.Errorf("adoption created %d account(s), want 0", got)
	}

	stored, err := f.users.GetUserByEmail(context.Background(), advVictimEmail)
	if err != nil {
		t.Fatalf("read the account back: %v", err)
	}
	if stored.ProviderSubject != advVictimSub {
		t.Errorf("persisted ProviderSubject = %q, want the backfilled subject %q",
			stored.ProviderSubject, advVictimSub)
	}
	if got := stored.Metadata[UserMetadataKeyProviderSubject]; got != advVictimSub {
		t.Errorf("persisted metadata subject = %v, want %q", got, advVictimSub)
	}

	// Pinned: the same connection asserting a different subject for the same
	// address is now the F-01 refusal again.
	req2 := f.beginRaw(t, AuthURLOptions{})
	other := advHonestUserInfo()
	other.Subject = "provider-subject-someone-else"
	f.idpAsserts(other, map[string]interface{}{"nonce": f.nonceOf(req2.State)})

	result, err = f.callback(req2.State, req2.Binding)
	advWantErr(t, err, ErrAccountLinkRequired)
	advWantNoResult(t, result)
}
