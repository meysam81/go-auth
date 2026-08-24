package provider

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authoidc "github.com/meysam81/go-auth/auth/oidc"
	"golang.org/x/oauth2"
)

// TestVerifyAuthorizedParty pins OIDC Core section 3.1.3.7 steps 4-5
// (finding F-19). Reverting verifyAuthorizedParty to "return nil" fails the
// first three cases.
func TestVerifyAuthorizedParty(t *testing.T) {
	t.Parallel()

	const clientID = "rp-under-test"

	tests := []struct {
		name     string
		audience []string
		claims   map[string]interface{}
		want     error
	}{
		{
			name:     "multi audience without azp is refused",
			audience: []string{clientID, "some-other-rp"},
			claims:   map[string]interface{}{},
			want:     ErrMissingAuthorizedParty,
		},
		{
			name:     "multi audience with azp naming another party is refused",
			audience: []string{clientID, "some-other-rp"},
			claims:   map[string]interface{}{"azp": "some-other-rp"},
			want:     ErrAuthorizedPartyMismatch,
		},
		{
			name:     "azp of the wrong type cannot suppress the check",
			audience: []string{clientID, "some-other-rp"},
			claims:   map[string]interface{}{"azp": nil},
			want:     ErrMissingAuthorizedParty,
		},
		{
			name:     "single audience with a wrong azp is still refused",
			audience: []string{clientID},
			claims:   map[string]interface{}{"azp": "some-other-rp"},
			want:     ErrAuthorizedPartyMismatch,
		},
		{
			name:     "single audience without azp is accepted",
			audience: []string{clientID},
			claims:   map[string]interface{}{},
			want:     nil,
		},
		{
			name:     "multi audience with a correct azp is accepted",
			audience: []string{clientID, "some-other-rp"},
			claims:   map[string]interface{}{"azp": clientID},
			want:     nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := verifyAuthorizedParty(clientID, tc.audience, tc.claims)
			if !errors.Is(got, tc.want) {
				t.Fatalf("verifyAuthorizedParty() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestBaseOIDCProviderRejectsForeignAudience is the end-to-end form of F-19: a
// correctly signed, unexpired token whose aud lists this client alongside
// another relying party, and whose azp names that other party. The signature
// and audience checks both pass; only the azp check stops it.
func TestBaseOIDCProviderRejectsForeignAudience(t *testing.T) {
	t.Parallel()

	idp := newFakeIDP(t)
	p, err := NewOIDCProviderWithClient(context.Background(), idp.server.Client(),
		"fake", idp.server.URL, idp.clientID, "secret", "https://rp.example/cb", []string{"openid"})
	if err != nil {
		t.Fatalf("NewOIDCProviderWithClient() error = %v", err)
	}

	tests := []struct {
		name   string
		claims map[string]interface{}
		want   error
	}{
		{
			name: "token minted for another relying party",
			claims: map[string]interface{}{
				"aud": []string{idp.clientID, "attacker-rp"},
				"azp": "attacker-rp",
			},
			want: ErrAuthorizedPartyMismatch,
		},
		{
			name: "multi audience with azp omitted",
			claims: map[string]interface{}{
				"aud": []string{idp.clientID, "attacker-rp"},
			},
			want: ErrMissingAuthorizedParty,
		},
		{
			name: "token minted for us",
			claims: map[string]interface{}{
				"aud": []string{idp.clientID, "attacker-rp"},
				"azp": idp.clientID,
			},
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			info, err := p.ExtractUserInfo(context.Background(), idp.token(t, tc.claims))
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Fatalf("ExtractUserInfo() error = %v, want %v", err, tc.want)
				}
				if info != nil {
					t.Fatalf("ExtractUserInfo() returned user info alongside an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ExtractUserInfo() error = %v, want nil", err)
			}
			if info.Subject != "subject-1" {
				t.Fatalf("Subject = %q, want %q", info.Subject, "subject-1")
			}
			if _, ok := info.RawClaims["nonce"]; !ok {
				t.Fatal("RawClaims lost the nonce claim the OIDC client verifies")
			}
		})
	}
}

// TestNewOIDCProviderBoundsEgress covers F-20: discovery must not run on
// http.DefaultClient. The supplied client is the only route to the fake IdP,
// so a regression that ignores it cannot reach the discovery document at all.
func TestNewOIDCProviderBoundsEgress(t *testing.T) {
	t.Parallel()

	idp := newFakeIDP(t)

	counting := &countingTransport{base: idp.server.Client().Transport}
	p, err := NewOIDCProviderWithClient(context.Background(), &http.Client{Transport: counting},
		"fake", idp.server.URL, idp.clientID, "secret", "https://rp.example/cb", []string{"openid"})
	if err != nil {
		t.Fatalf("NewOIDCProviderWithClient() error = %v", err)
	}
	if counting.calls == 0 {
		t.Fatal("discovery did not use the supplied client")
	}
	if p.HTTPClient() == nil {
		t.Fatal("HTTPClient() = nil, want the supplied client")
	}

	// The key set go-oidc builds captures the client at discovery time rather
	// than reading one from the verification context, so JWKS retrieval has to
	// be bounded here too.
	before := counting.calls
	if _, err := p.ExtractUserInfo(context.Background(), idp.token(t, nil)); err != nil {
		t.Fatalf("ExtractUserInfo() error = %v", err)
	}
	if counting.calls == before {
		t.Fatal("JWKS retrieval did not use the supplied client")
	}
}

func TestNewOIDCProviderRejectsEmptyClientID(t *testing.T) {
	t.Parallel()

	_, err := NewOIDCProvider(context.Background(), "fake", "https://idp.example", "", "s", "https://rp.example/cb", nil)
	if !errors.Is(err, ErrProviderMisconfigured) {
		t.Fatalf("NewOIDCProvider() error = %v, want %v", err, ErrProviderMisconfigured)
	}
}

func TestBaseOIDCProviderRejectsMissingIDToken(t *testing.T) {
	t.Parallel()

	idp := newFakeIDP(t)
	p, err := NewOIDCProviderWithClient(context.Background(), idp.server.Client(),
		"fake", idp.server.URL, idp.clientID, "secret", "https://rp.example/cb", []string{"openid"})
	if err != nil {
		t.Fatalf("NewOIDCProviderWithClient() error = %v", err)
	}

	if _, err := p.ExtractUserInfo(context.Background(), &oauth2.Token{AccessToken: "opaque"}); !errors.Is(err, ErrNoIDToken) {
		t.Fatalf("ExtractUserInfo() error = %v, want %v", err, ErrNoIDToken)
	}
	if _, err := p.ExtractUserInfo(context.Background(), nil); !errors.Is(err, ErrNoIDToken) {
		t.Fatalf("ExtractUserInfo(nil) error = %v, want %v", err, ErrNoIDToken)
	}
}

// TestOAuth2ProviderDeclinedResponse covers the nil-UserInfo-with-nil-error
// hole: an extract function that declines a response used to hand the caller a
// nil user and no error to notice it by.
func TestOAuth2ProviderDeclinedResponse(t *testing.T) {
	t.Parallel()

	srv := newJSONServer(t, http.StatusOK, `{"ok":false,"error":"invalid_auth"}`)
	p := NewOAuth2ProviderWithClient("fake", oauth2ConfigFor(srv.URL), srv.URL,
		func(map[string]interface{}) *authoidc.UserInfo { return nil }, srv.Client())

	info, err := p.ExtractUserInfo(context.Background(), staticToken())
	if !errors.Is(err, ErrNoUserInfo) {
		t.Fatalf("ExtractUserInfo() error = %v, want %v", err, ErrNoUserInfo)
	}
	if info != nil {
		t.Fatal("ExtractUserInfo() returned user info alongside an error")
	}
}

func TestOAuth2ProviderMissingExtractFunc(t *testing.T) {
	t.Parallel()

	srv := newJSONServer(t, http.StatusOK, `{}`)
	p := NewOAuth2Provider("fake", oauth2ConfigFor(srv.URL), srv.URL, nil)

	if _, err := p.ExtractUserInfo(context.Background(), staticToken()); !errors.Is(err, ErrProviderMisconfigured) {
		t.Fatalf("ExtractUserInfo() error = %v, want %v", err, ErrProviderMisconfigured)
	}
}

// TestOAuth2ProviderBoundsBody covers F-20's memory-exhaustion half. The
// client is deliberately unbounded so that only the io.LimitReader inside
// ExtractUserInfo can stop the response.
func TestOAuth2ProviderBoundsBody(t *testing.T) {
	t.Parallel()

	// The body never ends. Only the io.LimitReader stops it: without one,
	// io.ReadAll runs until the client's timeout, so removing the bound turns
	// this from a fast ErrUserInfoTooLarge into a slow timeout error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// A write error is the client having stopped reading, which is the
		// expected end of this response rather than a test failure.
		if _, err := w.Write([]byte(`{"padding":"`)); err != nil {
			return
		}
		chunk := []byte(strings.Repeat("a", 64*1024))
		for {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)

	// Deliberately unbounded: the transport must not be what stops this.
	p := NewOAuth2ProviderWithClient("fake", oauth2ConfigFor(srv.URL), srv.URL,
		func(map[string]interface{}) *authoidc.UserInfo { return &authoidc.UserInfo{Subject: "s"} },
		&http.Client{Timeout: 10 * time.Second})

	if _, err := p.ExtractUserInfo(context.Background(), staticToken()); !errors.Is(err, ErrUserInfoTooLarge) {
		t.Fatalf("ExtractUserInfo() error = %v, want %v", err, ErrUserInfoTooLarge)
	}
}

func TestOAuth2ProviderNonOKStatusIsTruncated(t *testing.T) {
	t.Parallel()

	body := strings.Repeat("z", 4096)
	srv := newJSONServer(t, http.StatusForbidden, body)
	p := NewOAuth2ProviderWithClient("fake", oauth2ConfigFor(srv.URL), srv.URL,
		func(map[string]interface{}) *authoidc.UserInfo { return &authoidc.UserInfo{Subject: "s"} }, srv.Client())

	_, err := p.ExtractUserInfo(context.Background(), staticToken())
	if err == nil {
		t.Fatal("ExtractUserInfo() error = nil, want a status error")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("error %q does not name the status", err)
	}
	if len(err.Error()) > userInfoErrorSnippetBytes+256 {
		t.Fatalf("error body was not truncated: %d bytes", len(err.Error()))
	}
}

func TestOAuth2ProviderSuccess(t *testing.T) {
	t.Parallel()

	srv := newJSONServer(t, http.StatusOK, `{"id":"u-1"}`)
	p := NewOAuth2ProviderWithClient("fake", oauth2ConfigFor(srv.URL), srv.URL,
		func(data map[string]interface{}) *authoidc.UserInfo {
			id, ok := data["id"].(string)
			if !ok {
				return nil
			}
			return &authoidc.UserInfo{Subject: id, RawClaims: data}
		}, srv.Client())

	info, err := p.ExtractUserInfo(context.Background(), staticToken())
	if err != nil {
		t.Fatalf("ExtractUserInfo() error = %v", err)
	}
	if info.Subject != "u-1" {
		t.Fatalf("Subject = %q, want %q", info.Subject, "u-1")
	}
}

// TestOAuth2ProviderClientPrecedence pins the rule in clientContext: an
// explicit client wins, an inherited one is not overridden by the default, and
// a provider used outside a callback still gets a bounded client rather than
// http.DefaultClient.
func TestOAuth2ProviderClientPrecedence(t *testing.T) {
	t.Parallel()

	explicit := &http.Client{}
	inherited := &http.Client{}

	tests := []struct {
		name     string
		provider *OAuth2Provider
		ctx      context.Context
		want     *http.Client
	}{
		{
			name:     "explicit client wins",
			provider: NewOAuth2ProviderWithClient("p", &oauth2.Config{}, "https://u.example", nil, explicit),
			ctx:      context.WithValue(context.Background(), oauth2.HTTPClient, inherited),
			want:     explicit,
		},
		{
			name:     "inherited client is kept",
			provider: NewOAuth2Provider("p", &oauth2.Config{}, "https://u.example", nil),
			ctx:      context.WithValue(context.Background(), oauth2.HTTPClient, inherited),
			want:     inherited,
		},
		{
			name:     "bare context gets the bounded default",
			provider: NewOAuth2Provider("p", &oauth2.Config{}, "https://u.example", nil),
			ctx:      context.Background(),
			want:     defaultHTTPClient(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := tc.provider.clientContext(tc.ctx).Value(oauth2.HTTPClient).(*http.Client)
			if !ok {
				t.Fatal("clientContext() put no HTTP client on the context")
			}
			if got != tc.want {
				t.Fatalf("clientContext() client = %p, want %p", got, tc.want)
			}
			if got == http.DefaultClient {
				t.Fatal("clientContext() left the request on http.DefaultClient")
			}
		})
	}
}

// TestVendorExtractorsDeclineUnusableResponses covers the vendor parsers that
// used to manufacture a subject-less user out of a failure response. Each now
// declines, which ExtractUserInfo reports as ErrNoUserInfo.
func TestVendorExtractorsDeclineUnusableResponses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		build    func(url string) *OAuth2Provider
		body     string
		wantUser bool
	}{
		{
			name:  "slack application level failure inside a 200",
			build: func(string) *OAuth2Provider { return NewSlackProvider("id", "secret", "https://rp.example/cb") },
			body:  `{"ok":false,"error":"invalid_auth"}`,
		},
		{
			name:  "slack success",
			build: func(string) *OAuth2Provider { return NewSlackProvider("id", "secret", "https://rp.example/cb") },
			body: `{"ok":true,"user":{"id":"U1","name":"jo","email":"jo@example.com"},` +
				`"team":{"id":"T1"}}`,
			wantUser: true,
		},
		{
			name:  "github response without an id",
			build: func(string) *OAuth2Provider { return NewGitHubProvider("id", "secret", "https://rp.example/cb") },
			body:  `{"message":"Bad credentials"}`,
		},
		{
			name:  "discord response without an id",
			build: func(string) *OAuth2Provider { return NewDiscordProvider("id", "secret", "https://rp.example/cb") },
			body:  `{"message":"401: Unauthorized"}`,
		},
		{
			name:  "linkedin response without a sub",
			build: func(string) *OAuth2Provider { return NewLinkedInProvider("id", "secret", "https://rp.example/cb") },
			body:  `{"serviceErrorCode":65600}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := newJSONServer(t, http.StatusOK, tc.body)
			p := tc.build(srv.URL)
			// Point the vendor provider at the fake endpoint without touching
			// its parser, which is what is under test.
			p.userInfoURL = srv.URL
			p.httpClient = srv.Client()

			info, err := p.ExtractUserInfo(context.Background(), staticToken())
			if tc.wantUser {
				if err != nil {
					t.Fatalf("ExtractUserInfo() error = %v", err)
				}
				if info == nil || info.Subject == "" {
					t.Fatal("ExtractUserInfo() returned no subject for a usable response")
				}
				return
			}
			if !errors.Is(err, ErrNoUserInfo) {
				t.Fatalf("ExtractUserInfo() error = %v, want %v", err, ErrNoUserInfo)
			}
			if info != nil {
				t.Fatal("ExtractUserInfo() returned user info alongside an error")
			}
		})
	}
}

// TestGitHubEmailVerifiedTracksTheAddress pins the F-01-adjacent fix: /user
// carries no email_verified claim, so an absent address must not be reported
// as a verified one.
func TestGitHubEmailVerifiedTracksTheAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		body         string
		wantEmail    string
		wantVerified bool
	}{
		{
			name:         "no public email",
			body:         `{"id":1,"login":"jo","email":null}`,
			wantVerified: false,
		},
		{
			name:         "public email",
			body:         `{"id":1,"login":"jo","email":"jo@example.com"}`,
			wantEmail:    "jo@example.com",
			wantVerified: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := newJSONServer(t, http.StatusOK, tc.body)
			p := NewGitHubProvider("id", "secret", "https://rp.example/cb")
			p.userInfoURL = srv.URL
			p.httpClient = srv.Client()

			info, err := p.ExtractUserInfo(context.Background(), staticToken())
			if err != nil {
				t.Fatalf("ExtractUserInfo() error = %v", err)
			}
			if info.Email != tc.wantEmail {
				t.Fatalf("Email = %q, want %q", info.Email, tc.wantEmail)
			}
			if info.EmailVerified != tc.wantVerified {
				t.Fatalf("EmailVerified = %v, want %v", info.EmailVerified, tc.wantVerified)
			}
		})
	}
}

// --- helpers ---

type countingTransport struct {
	base  http.RoundTripper
	calls int
}

func (t *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.calls++
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

func newJSONServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if _, err := w.Write([]byte(body)); err != nil {
			t.Errorf("write test response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func oauth2ConfigFor(base string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     "id",
		ClientSecret: "secret",
		Endpoint:     oauth2.Endpoint{AuthURL: base + "/authorize", TokenURL: base + "/token"},
	}
}

func staticToken() *oauth2.Token {
	// A zero Expiry means "does not expire" to golang.org/x/oauth2, so no
	// refresh is attempted and the request is made with this token as-is.
	return &oauth2.Token{AccessToken: "access-token", TokenType: "Bearer"}
}

// fakeIDP is a minimal OpenID provider: a discovery document, a JWKS, and the
// ability to mint an ID token this test controls every claim of.
type fakeIDP struct {
	server   *httptest.Server
	key      *rsa.PrivateKey
	clientID string
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	idp := &fakeIDP{key: key, clientID: "rp-under-test"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		idp.writeJSON(t, w, map[string]interface{}{
			"issuer":                                idp.server.URL,
			"authorization_endpoint":                idp.server.URL + "/authorize",
			"token_endpoint":                        idp.server.URL + "/token",
			"jwks_uri":                              idp.server.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		idp.writeJSON(t, w, map[string]interface{}{
			"keys": []map[string]string{{
				"kty": "RSA",
				"kid": "test-key",
				"use": "sig",
				"alg": "RS256",
				"n":   b64(key.N.Bytes()),
				"e":   b64(big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	})

	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

func (f *fakeIDP) writeJSON(t *testing.T, w http.ResponseWriter, doc map[string]interface{}) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(doc); err != nil {
		t.Errorf("encode test document: %v", err)
	}
}

// token mints a signed ID token, applying overrides on top of a valid claim
// set so a test only has to state the part it is attacking.
func (f *fakeIDP) token(t *testing.T, overrides map[string]interface{}) *oauth2.Token {
	t.Helper()

	now := time.Now()
	claims := map[string]interface{}{
		"iss":            f.server.URL,
		"aud":            []string{f.clientID},
		"sub":            "subject-1",
		"exp":            now.Add(time.Hour).Unix(),
		"iat":            now.Unix(),
		"nonce":          "nonce-value",
		"email":          "jo@example.com",
		"email_verified": true,
	}
	for k, v := range overrides {
		claims[k] = v
	}

	header := b64(mustJSON(t, map[string]string{"alg": "RS256", "typ": "JWT", "kid": "test-key"}))
	payload := b64(mustJSON(t, claims))
	signingInput := header + "." + payload

	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15() error = %v", err)
	}

	raw := signingInput + "." + b64(sig)
	return (&oauth2.Token{AccessToken: "access-token", TokenType: "Bearer"}).
		WithExtra(map[string]interface{}{"id_token": raw})
}

func mustJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return out
}

func b64(in []byte) string { return base64.RawURLEncoding.EncodeToString(in) }
