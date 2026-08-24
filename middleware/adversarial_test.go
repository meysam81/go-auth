package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	authjwt "github.com/meysam81/go-auth/auth/jwt"
	"github.com/meysam81/go-auth/storage"
)

// This file is the adversarial half of the middleware test program
// (docs/security-hardening.md section 6). Each test names the attack class it
// defends against and is written to fail when the corresponding fix is reverted.

const (
	adversarialIssuer   = "https://auth.example.test"
	adversarialAudience = "https://api.example.test"
)

// adversarialSigningKey is the HMAC secret the fixture manager is built with, so
// a test can mint a token that is correctly SIGNED and wrong in every other way.
// A forgery that fails at the signature proves nothing about the claim checks.
var adversarialSigningKey = []byte("0123456789abcdef0123456789abcdef")

// attackerSigningKey stands in for a secret the attacker chose themselves.
var attackerSigningKey = []byte("attacker-attacker-attacker-atta!")

// newAdversarialJWT builds a token manager and the user its tokens name.
func newAdversarialJWT(t *testing.T) (*authjwt.TokenManager, *storage.User) {
	t.Helper()

	userStore := storage.NewInMemoryUserStore()
	user := &storage.User{ID: "u1", Email: "victim@example.test"}
	if err := userStore.CreateUser(context.Background(), user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	manager, err := authjwt.NewTokenManager(authjwt.Config{
		UserStore:  userStore,
		TokenStore: storage.NewInMemoryTokenStore(),
		SigningKey: adversarialSigningKey,
		Issuer:     adversarialIssuer,
		Audience:   []string{adversarialAudience},
	})
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}

	return manager, user
}

// accessClaims returns the claim set of a token this library would accept. Each
// hostile case below changes exactly one thing about it, so a rejection can only
// be attributed to that change.
func accessClaims() gojwt.MapClaims {
	now := time.Now()
	return gojwt.MapClaims{
		"uid":  "u1",
		"sub":  "u1",
		"type": "access",
		"iss":  adversarialIssuer,
		"aud":  []string{adversarialAudience},
		"iat":  now.Unix(),
		"nbf":  now.Unix(),
		"exp":  now.Add(15 * time.Minute).Unix(),
	}
}

// craftToken signs an arbitrary claim set. It is the attacker's minting
// function: it can produce claim shapes the library's own Claims struct cannot.
func craftToken(t *testing.T, method gojwt.SigningMethod, key any, claims gojwt.MapClaims) string {
	t.Helper()

	signed, err := gojwt.NewWithClaims(method, claims).SignedString(key)
	if err != nil {
		t.Fatalf("craft token: %v", err)
	}

	return signed
}

// serveWithBearer runs one request through JWTMiddleware and reports whether the
// protected handler was reached, along with the response.
func serveWithBearer(t *testing.T, mw *JWTMiddleware, header string, setHeader bool) (bool, *httptest.ResponseRecorder) {
	t.Helper()

	reached := false
	handler := mw.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		reached = true
		if _, ok := GetUserID(r); !ok {
			t.Error("handler was reached without a user ID in context")
		}
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	if setHeader {
		req.Header.Set("Authorization", header)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	return reached, rec
}

// ---------------------------------------------------------------------------
// F-02 -- a refresh token authenticating as an access token (CWE-863)
// ---------------------------------------------------------------------------

// TestMiddleware_RefreshTokenAsBearerCredentialIsRejected is the regression test
// for the one finding in this audit that was proven by execution rather than by
// reading: a refresh token presented in the Authorization header authorized
// every route JWTMiddleware protects (F-02, CWE-863 incorrect authorization).
//
// A refresh token lives for seven days against an access token's fifteen
// minutes, is the credential most likely to be sitting in client storage, and
// exists to be presented to exactly one endpoint. Accepting it as a bearer
// credential turns the least-guarded long-lived secret in the system into a
// universal one.
//
// The fix is the token-type pin in the JWT verifier plus the middleware's
// access-token-only entry point. Remove the type check and this test authorizes
// a refresh token.
func TestMiddleware_RefreshTokenAsBearerCredentialIsRejected(t *testing.T) {
	t.Parallel()

	manager, user := newAdversarialJWT(t)
	pair, err := manager.GenerateTokenPair(context.Background(), user)
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}
	mw := NewJWTMiddleware(JWTConfig{TokenManager: manager})

	reached, rec := serveWithBearer(t, mw, "Bearer "+pair.RefreshToken, true)
	if reached {
		t.Fatal("a refresh token authorized a request protected by JWTMiddleware")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	// The denial must not describe why. "this is a refresh token" tells an
	// attacker holding a stolen blob exactly which endpoint to replay it against.
	if body := rec.Body.String(); strings.Contains(strings.ToLower(body), "refresh") || strings.Contains(body, pair.RefreshToken) {
		t.Fatalf("the denial leaked detail about the credential: %q", body)
	}

	// The same credential must still work where it belongs, or the fix is just a
	// broken refresh flow.
	if _, err := manager.RefreshAccessToken(context.Background(), pair.RefreshToken); err != nil {
		t.Fatalf("refresh token no longer works on the refresh path: %v", err)
	}
}

// TestMiddleware_HostileTokenClaimsAreRejected walks the claim-level forgeries a
// bearer-token verifier has to survive. Every token here is signed with the
// server's own key unless the row says otherwise, so nothing is rejected by
// accident of a bad signature.
//
// Rows in order: the F-02 refresh token expressed as a raw claim set; a token
// type stripped, nulled, case-folded, padded or NUL-terminated (the string
// comparison must be exact, since "Access" and "access " are what a lenient
// parser accepts); a token type that is not a string at all, which is the
// type-confusion class where a verifier that reads a claim without asserting its
// JSON type can be fed an array or a number; the unsecured "alg":"none" token of
// RFC 7519 section 6, still the single most-exploited JWT forgery; a token
// signed with a key the attacker chose; and the temporal claims -- expired,
// not-yet-valid, and no expiry at all, which is a token that never dies.
func TestMiddleware_HostileTokenClaimsAreRejected(t *testing.T) {
	t.Parallel()

	manager, user := newAdversarialJWT(t)
	mw := NewJWTMiddleware(JWTConfig{TokenManager: manager})

	valid, err := manager.GenerateAccessToken(context.Background(), user)
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}

	mutate := func(f func(gojwt.MapClaims)) string {
		claims := accessClaims()
		f(claims)
		return craftToken(t, gojwt.SigningMethodHS256, adversarialSigningKey, claims)
	}

	tests := []struct {
		name  string
		token string
	}{
		{"type claim says refresh", mutate(func(c gojwt.MapClaims) { c["type"] = "refresh" })},
		{"type claim absent", mutate(func(c gojwt.MapClaims) { delete(c, "type") })},
		{"type claim is null", mutate(func(c gojwt.MapClaims) { c["type"] = nil })},
		{"type claim is empty", mutate(func(c gojwt.MapClaims) { c["type"] = "" })},
		{"type claim is case-folded", mutate(func(c gojwt.MapClaims) { c["type"] = "Access" })},
		{"type claim is padded", mutate(func(c gojwt.MapClaims) { c["type"] = "access " })},
		{"type claim is NUL-terminated", mutate(func(c gojwt.MapClaims) { c["type"] = "access\x00" })},
		{"type claim is an array", mutate(func(c gojwt.MapClaims) { c["type"] = []string{"access"} })},
		{"type claim is a number", mutate(func(c gojwt.MapClaims) { c["type"] = 1 })},
		{"expired an hour ago", mutate(func(c gojwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() })},
		{"not valid until tomorrow", mutate(func(c gojwt.MapClaims) { c["nbf"] = time.Now().Add(24 * time.Hour).Unix() })},
		{"no expiry at all", mutate(func(c gojwt.MapClaims) { delete(c, "exp") })},
		{"issued by another service sharing the secret", mutate(func(c gojwt.MapClaims) { c["iss"] = "https://evil.example.test" })},
		{"minted for another audience", mutate(func(c gojwt.MapClaims) { c["aud"] = []string{"https://other.example.test"} })},
		{
			name:  "unsecured alg none",
			token: craftToken(t, gojwt.SigningMethodNone, gojwt.UnsafeAllowNoneSignatureType, accessClaims()),
		},
		{
			name:  "signed with the attacker's own key",
			token: craftToken(t, gojwt.SigningMethodHS256, attackerSigningKey, accessClaims()),
		},
		{"signature stripped", valid[:strings.LastIndex(valid, ".")+1]},
		{"truncated mid-payload", valid[:len(valid)/2]},
		{"not a token at all", "definitely-not-a-jwt"},
		{"empty credential", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			reached, rec := serveWithBearer(t, mw, "Bearer "+tc.token, true)
			if reached {
				t.Fatal("hostile token authorized the request")
			}
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
			}
		})
	}

	// The control: with the type pin in place a genuine access token must still
	// authorize, or "reject everything" would pass every row above.
	t.Run("genuine access token", func(t *testing.T) {
		t.Parallel()

		reached, rec := serveWithBearer(t, mw, "Bearer "+valid, true)
		if !reached {
			t.Fatalf("a valid access token was refused: status %d", rec.Code)
		}
	})
}

// TestMiddleware_OversizedCredentialIsRejectedPromptly: an unauthenticated
// caller controls the entire Authorization header, so every byte of it is
// attacker-chosen input to a parser. JWT libraries have shipped advisories for
// exactly this shape -- unbounded work or allocation while parsing an oversized
// or pathologically punctuated credential -- so the guard is that a megabyte of
// garbage is refused, and refused quickly, rather than turned into work.
func TestMiddleware_OversizedCredentialIsRejectedPromptly(t *testing.T) {
	t.Parallel()

	manager, _ := newAdversarialJWT(t)
	mw := NewJWTMiddleware(JWTConfig{TokenManager: manager})

	blob := strings.Repeat("A", 1<<20)
	credentials := []struct {
		name  string
		value string
	}{
		{"one megabyte of padding", blob},
		{"three oversized segments", blob + "." + blob + "." + blob},
		{"many empty segments", strings.Repeat(".", 100000)},
	}

	for _, cred := range credentials {
		t.Run(cred.name, func(t *testing.T) {
			t.Parallel()

			start := time.Now()
			reached, rec := serveWithBearer(t, mw, "Bearer "+cred.value, true)
			elapsed := time.Since(start)

			if reached {
				t.Fatal("an oversized credential authorized the request")
			}
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
			}
			if elapsed > 2*time.Second {
				t.Fatalf("refusing %d bytes of credential took %v", len(cred.value), elapsed)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Authorization header parsing
// ---------------------------------------------------------------------------

// TestMiddleware_AuthorizationHeaderAttacks covers the credential-parsing
// surface of HeaderExtractor against RFC 9110 section 11.1, which makes the
// auth-scheme case-insensitive, and RFC 6750 section 2.1, whose Bearer grammar
// is "Bearer" 1*SP b64token -- a credential that cannot contain a space.
//
// Two properties are asserted. A malformed or wrongly-schemed header yields no
// credential at all. A well-formed one yields the bytes that followed the
// scheme, VERBATIM: an extractor that trims, folds or reassembles a credential
// disagrees with every other component that parses the same header, and a parser
// differential over a credential is how one layer's "no token" becomes another
// layer's "valid token".
func TestMiddleware_AuthorizationHeaderAttacks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		header    string
		setHeader bool
		wantToken string
		wantErr   bool
	}{
		{name: "header absent", wantErr: true},
		{name: "header present but empty", setHeader: true, wantErr: true},
		{name: "scheme only", header: "Bearer", setHeader: true, wantErr: true},
		{name: "scheme with no separator", header: "Bearertoken", setHeader: true, wantErr: true},
		{name: "wrong scheme", header: "Basic dXNlcjpwYXNzd29yZA==", setHeader: true, wantErr: true},
		{name: "scheme name is a prefix of ours", header: "BearerToken abc", setHeader: true, wantErr: true},
		{name: "unknown scheme carrying our token", header: "Token abc", setHeader: true, wantErr: true},
		{name: "whitespace only", header: "   ", setHeader: true, wantErr: true},

		// RFC 9110 section 11.1: scheme names are case-insensitive, so a client
		// sending "bearer" is conformant and must not be locked out.
		{name: "lower-case scheme is accepted", header: "bearer abc", setHeader: true, wantToken: "abc"},
		{name: "upper-case scheme is accepted", header: "BEARER abc", setHeader: true, wantToken: "abc"},
		{name: "mixed-case scheme is accepted", header: "BeArEr abc", setHeader: true, wantToken: "abc"},

		// Nothing usable is handed on, and nothing is silently repaired.
		{name: "scheme and separator with no credential", header: "Bearer ", setHeader: true, wantToken: ""},
		{name: "extra separator is not trimmed away", header: "Bearer  abc", setHeader: true, wantToken: " abc"},
		{name: "credential containing a space is not split", header: "Bearer abc def", setHeader: true, wantToken: "abc def"},
		{name: "repeated scheme is not unwrapped", header: "Bearer Bearer abc", setHeader: true, wantToken: "Bearer abc"},
		{name: "tab is not a separator", header: "Bearer\tabc", setHeader: true, wantErr: true},
	}

	extractor := &HeaderExtractor{HeaderName: "Authorization", Scheme: "Bearer"}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			if tc.setHeader {
				req.Header.Set("Authorization", tc.header)
			}

			got, err := extractor.Extract(req)
			if tc.wantErr {
				if !errors.Is(err, ErrUnauthorized) {
					t.Fatalf("err = %v, want ErrUnauthorized", err)
				}
				if got != "" {
					t.Fatalf("a rejected header still yielded the credential %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v, want the credential to be extracted", err)
			}
			if got != tc.wantToken {
				t.Fatalf("credential = %q, want %q verbatim", got, tc.wantToken)
			}
		})
	}
}

// TestMiddleware_MalformedHeaderNeverAuthorizes closes the loop end to end: an
// empty credential must reach no store lookup and no handler. A credential of ""
// forwarded into a verifier is how an empty-key row, a cache miss returning a
// zero value, or a store that treats "" as a wildcard becomes an authentication
// bypass, so the request must be refused whether or not the extractor called it
// an error.
func TestMiddleware_MalformedHeaderNeverAuthorizes(t *testing.T) {
	t.Parallel()

	manager, _ := newAdversarialJWT(t)
	mw := NewJWTMiddleware(JWTConfig{TokenManager: manager})

	headers := []string{"", "Bearer", "Bearer ", "Bearer  ", "bearer ", "Basic  ", "Bearer\x00", "Bearer null"}

	for _, header := range headers {
		t.Run("header="+strings.ReplaceAll(header, " ", "_"), func(t *testing.T) {
			t.Parallel()

			reached, rec := serveWithBearer(t, mw, header, true)
			if reached {
				t.Fatalf("malformed header %q authorized the request", header)
			}
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Cookie extraction
// ---------------------------------------------------------------------------

// TestMiddleware_CookieExtractorAttacks: a cleared session cookie is a PRESENT
// cookie with an empty value, so an extractor that only checks presence forwards
// "" as a credential -- the empty-key lookup again. Cookie names are compared as
// octets (RFC 6265 section 4.1.1 defines the name as a token and nothing
// case-folds it), so a differently-cased or differently-spelled cookie must not
// be picked up: a subdomain an attacker controls can set cookies on the parent
// domain, and name confusion is how their cookie gets read instead of ours.
func TestMiddleware_CookieExtractorAttacks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cookies   []*http.Cookie
		wantToken string
		wantErr   bool
	}{
		{name: "no cookies at all", wantErr: true},
		{
			name:    "cookie missing, others present",
			cookies: []*http.Cookie{{Name: "csrf", Value: "abc"}, {Name: "theme", Value: "dark"}},
			wantErr: true,
		},
		{
			name:    "cookie present but empty",
			cookies: []*http.Cookie{{Name: "session_id", Value: ""}},
			wantErr: true,
		},
		{
			name:    "name differs in case",
			cookies: []*http.Cookie{{Name: "SESSION_ID", Value: "attacker"}},
			wantErr: true,
		},
		{
			name:    "name is a prefix of ours",
			cookies: []*http.Cookie{{Name: "session_id_2", Value: "attacker"}},
			wantErr: true,
		},
		{
			name:      "value is passed on verbatim",
			cookies:   []*http.Cookie{{Name: "session_id", Value: "AbC-123_xyz"}},
			wantToken: "AbC-123_xyz",
		},
		{
			// RFC 6265 section 5.4 lets a user agent send several cookies of one
			// name; an attacker who can write a cookie on a sibling host uses that
			// to shadow the real one. Whichever is chosen must be one of the two
			// sent, never a concatenation of both, which would be a credential no
			// store ever issued.
			name: "shadowed by a duplicate name",
			cookies: []*http.Cookie{
				{Name: "session_id", Value: "genuine"},
				{Name: "session_id", Value: "planted"},
			},
			wantToken: "genuine",
		},
	}

	extractor := &CookieExtractor{CookieName: "session_id"}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			for _, cookie := range tc.cookies {
				req.AddCookie(cookie)
			}

			got, err := extractor.Extract(req)
			if tc.wantErr {
				if !errors.Is(err, ErrUnauthorized) {
					t.Fatalf("err = %v, want ErrUnauthorized", err)
				}
				if got != "" {
					t.Fatalf("a rejected cookie still yielded %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v, want the cookie value", err)
			}
			if got != tc.wantToken {
				t.Fatalf("credential = %q, want %q", got, tc.wantToken)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// MultiExtractor ordering
// ---------------------------------------------------------------------------

// recordingExtractor counts how many times it was consulted.
type recordingExtractor struct {
	token string
	err   error
	calls int
}

func (e *recordingExtractor) Extract(*http.Request) (string, error) {
	e.calls++
	return e.token, e.err
}

// TestMiddleware_MultiExtractorStopsAtTheFirstSuccess pins the precedence of a
// multi-source credential reader. Order is a security property: when a route
// accepts both a cookie and a header, whichever is consulted first decides which
// credential wins, and an attacker who can plant one of the two relies on the
// order being ambiguous. Later extractors must not run at all -- consulting them
// after a decision has been made is how a second, attacker-planted credential
// gets a chance to overwrite the first.
func TestMiddleware_MultiExtractorStopsAtTheFirstSuccess(t *testing.T) {
	t.Parallel()

	first := &recordingExtractor{token: "from-first"}
	second := &recordingExtractor{token: "from-second"}
	third := &recordingExtractor{token: "from-third"}

	multi := &MultiExtractor{Extractors: []SessionTokenExtractor{first, second, third}}
	got, err := multi.Extract(httptest.NewRequest(http.MethodGet, "/", http.NoBody))
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if got != "from-first" {
		t.Fatalf("credential = %q, want the first extractor's", got)
	}
	if second.calls != 0 || third.calls != 0 {
		t.Fatalf("later extractors were consulted after a decision: second=%d third=%d", second.calls, third.calls)
	}
}

// TestMiddleware_MultiExtractorFailsClosed: every extractor failing must deny,
// and the denial must not describe which one failed or why. The individual
// errors name whether a cookie was present, whether a header was malformed and
// which credential shapes the route accepts -- an enumeration oracle for an
// unauthenticated caller (CWE-209, information exposure through an error
// message). An empty extractor list must also deny rather than fall through.
func TestMiddleware_MultiExtractorFailsClosed(t *testing.T) {
	t.Parallel()

	secret := errors.New("cookie sess_v2 is malformed on host internal.example.test")
	first := &recordingExtractor{err: secret}
	second := &recordingExtractor{err: ErrUnauthorized}

	multi := &MultiExtractor{Extractors: []SessionTokenExtractor{first, second}}
	got, err := multi.Extract(httptest.NewRequest(http.MethodGet, "/", http.NoBody))
	if got != "" {
		t.Fatalf("credential = %q, want none", got)
	}
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
	if errors.Is(err, secret) || strings.Contains(err.Error(), "internal.example.test") {
		t.Fatalf("the denial leaked an extractor's internal error: %v", err)
	}
	if first.calls != 1 || second.calls != 1 {
		t.Fatalf("every extractor must be consulted before denying: first=%d second=%d", first.calls, second.calls)
	}

	empty := &MultiExtractor{}
	if _, err := empty.Extract(httptest.NewRequest(http.MethodGet, "/", http.NoBody)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("a MultiExtractor with no extractors returned %v, want ErrUnauthorized", err)
	}
}

// TestMiddleware_ExtractorReturningAnEmptyCredentialNeverAuthorizes: an
// extractor is caller-supplied code, so the middleware may not assume a nil
// error means a usable credential. Forwarding "" into a verifier is the
// empty-key bypass.
func TestMiddleware_ExtractorReturningAnEmptyCredentialNeverAuthorizes(t *testing.T) {
	t.Parallel()

	manager, _ := newAdversarialJWT(t)
	mw := NewJWTMiddleware(JWTConfig{
		TokenManager: manager,
		Extractor:    &recordingExtractor{token: ""},
	})

	reached := false
	handler := mw.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if reached {
		t.Fatal("an empty credential authorized the request")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// ---------------------------------------------------------------------------
// Cookie writing: logout completeness and the insecure zero value
// ---------------------------------------------------------------------------

// TestMiddleware_ClearMirrorsEveryAttributeWrittenIsRequiredForLogout: a user
// agent identifies a cookie by (name, domain, path), so a deletion that omits
// any of the three creates a SECOND, differently scoped cookie and leaves the
// live session identifier in place. The symptom is a logout that returns 200 and
// revokes nothing -- incomplete cleanup, CWE-459, reachable by anyone who
// obtained the identifier before the user pressed the button.
//
// Every attribute Write emits is compared against the one Clear emits across a
// matrix of configurations. Drop Path, Domain, Secure, HttpOnly or SameSite from
// Clear and the matching row fails.
func TestMiddleware_ClearMirrorsEveryAttributeWritten(t *testing.T) {
	t.Parallel()

	writers := []struct {
		name   string
		writer *CookieWriter
	}{
		{"host-only, root path", &CookieWriter{CookieName: "session_id", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}},
		{"domain-scoped", &CookieWriter{CookieName: "session_id", Path: "/", Domain: "example.test", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}},
		{"sub-path", &CookieWriter{CookieName: "session_id", Path: "/app/admin", Secure: true, HttpOnly: true, SameSite: http.SameSiteNoneMode}},
		{"max-age set", &CookieWriter{CookieName: "session_id", Path: "/", MaxAge: 3600, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}},
		{"insecure literal", &CookieWriter{CookieName: "session_id"}},
	}

	for _, tc := range writers {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			written := emitCookie(t, func(rw http.ResponseWriter) { tc.writer.Write(rw, "session-value") })
			cleared := emitCookie(t, tc.writer.Clear)

			if cleared.Name != written.Name {
				t.Errorf("Clear name = %q, Write name = %q", cleared.Name, written.Name)
			}
			if cleared.Path != written.Path {
				t.Errorf("Clear path = %q, Write path = %q: the live cookie survives", cleared.Path, written.Path)
			}
			if cleared.Domain != written.Domain {
				t.Errorf("Clear domain = %q, Write domain = %q: the live cookie survives", cleared.Domain, written.Domain)
			}
			if cleared.Secure != written.Secure {
				t.Errorf("Clear secure = %v, Write secure = %v", cleared.Secure, written.Secure)
			}
			if cleared.HttpOnly != written.HttpOnly {
				t.Errorf("Clear httpOnly = %v, Write httpOnly = %v", cleared.HttpOnly, written.HttpOnly)
			}
			if cleared.SameSite != written.SameSite {
				t.Errorf("Clear sameSite = %v, Write sameSite = %v", cleared.SameSite, written.SameSite)
			}

			// The deletion itself: no value, an immediate Max-Age and an expiry in
			// the past, because user agents have honored one or the other.
			if cleared.Value != "" {
				t.Errorf("Clear value = %q, want empty", cleared.Value)
			}
			if cleared.MaxAge >= 0 {
				t.Errorf("Clear max-age = %d, want a negative value", cleared.MaxAge)
			}
			if cleared.Expires.IsZero() || !cleared.Expires.Before(time.Now()) {
				t.Errorf("Clear expires = %v, want an instant in the past", cleared.Expires)
			}
		})
	}
}

// emitCookie runs a writer against a recorder and parses the single Set-Cookie
// header it produced.
func emitCookie(t *testing.T, write func(http.ResponseWriter)) *http.Cookie {
	t.Helper()

	rec := httptest.NewRecorder()
	write(rec)

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("emitted %d cookies, want exactly 1 (headers: %v)", len(cookies), rec.Header().Values("Set-Cookie"))
	}

	return cookies[0]
}

// TestMiddleware_ZeroValueCookieWriterIsInsecureAsDocumented asserts the warning
// on CookieWriter stays true. Secure, HttpOnly and SameSite are plain fields, so
// a literal that omits them emits a session identifier that travels over
// cleartext HTTP (CWE-614), is readable by any script on the page (CWE-1004) and
// rides along on cross-site requests (CWE-1275).
//
// The field types are frozen by v1 compatibility and their defaults cannot be
// inverted, so this test exists to make the documented hazard load-bearing: if
// the zero value ever becomes safe, the doc comment steering callers to
// NewSecureCookieWriter is stale and this test says so.
func TestMiddleware_ZeroValueCookieWriterIsInsecureAsDocumented(t *testing.T) {
	t.Parallel()

	zero := &CookieWriter{CookieName: "session_id"}
	if zero.Secure || zero.HttpOnly || zero.SameSite != 0 {
		t.Fatalf("the zero value is no longer insecure (%+v); the documented warning is now wrong", zero)
	}

	raw := rawSetCookie(t, func(rw http.ResponseWriter) { zero.Write(rw, "session-value") })
	for _, attr := range []string{"Secure", "HttpOnly", "SameSite"} {
		if strings.Contains(raw, attr) {
			t.Fatalf("zero-value writer emitted %s (%q); update CookieWriter's warning", attr, raw)
		}
	}

	secure, err := NewSecureCookieWriter(SecureCookieConfig{CookieName: "__Host-session"})
	if err != nil {
		t.Fatalf("NewSecureCookieWriter: %v", err)
	}
	if !secure.Secure || !secure.HttpOnly {
		t.Fatalf("the secure constructor left the cookie exposed: %+v", secure)
	}
	if secure.SameSite != http.SameSiteLaxMode {
		t.Fatalf("SameSite = %v, want Lax by default", secure.SameSite)
	}
	if secure.Path != "/" {
		t.Fatalf("Path = %q, want / so the __Host- prefix holds", secure.Path)
	}

	secureRaw := rawSetCookie(t, func(rw http.ResponseWriter) { secure.Write(rw, "session-value") })
	for _, attr := range []string{"Secure", "HttpOnly", "SameSite=Lax"} {
		if !strings.Contains(secureRaw, attr) {
			t.Fatalf("secure writer omitted %s: %q", attr, secureRaw)
		}
	}
}

// rawSetCookie returns the single Set-Cookie header a writer produced.
func rawSetCookie(t *testing.T, write func(http.ResponseWriter)) string {
	t.Helper()

	rec := httptest.NewRecorder()
	write(rec)

	headers := rec.Header().Values("Set-Cookie")
	if len(headers) != 1 {
		t.Fatalf("emitted %d Set-Cookie headers, want 1: %v", len(headers), headers)
	}

	return headers[0]
}

// TestMiddleware_SecureCookieWriterRejectsUnemittableConfigurations: both
// failure modes this constructor guards are INVISIBLE at runtime. net/http drops
// a Set-Cookie whose name is not an RFC 6265 section 4.1.1 token without a word,
// and a user agent discards a __Host- cookie that is not host-only and Path=/
// (the cookie-name-prefix rules of RFC 6265bis section 4.1.3.2). Either way the
// only symptom is a session that never sticks, so a rejected configuration must
// fail at construction and must not yield a writer.
func TestMiddleware_SecureCookieWriterRejectsUnemittableConfigurations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  SecureCookieConfig
	}{
		{"empty name", SecureCookieConfig{}},
		{"name with a space", SecureCookieConfig{CookieName: "session id"}},
		{"name with a semicolon", SecureCookieConfig{CookieName: "session;id"}},
		{"name with an equals sign", SecureCookieConfig{CookieName: "session=id"}},
		{"name with a comma", SecureCookieConfig{CookieName: "session,id"}},
		{"name with a control character", SecureCookieConfig{CookieName: "session\x01id"}},
		{"name with CR LF", SecureCookieConfig{CookieName: "session\r\nSet-Cookie: evil=1"}},
		{"name with DEL", SecureCookieConfig{CookieName: "session\x7fid"}},
		{"name with a high byte", SecureCookieConfig{CookieName: "session\xffid"}},
		{"__Host- with a domain", SecureCookieConfig{CookieName: "__Host-session", Domain: "example.test"}},
		{"__Host- with a sub-path", SecureCookieConfig{CookieName: "__Host-session", Path: "/app"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			writer, err := NewSecureCookieWriter(tc.cfg)
			if !errors.Is(err, ErrInvalidCookieConfig) {
				t.Fatalf("err = %v, want ErrInvalidCookieConfig", err)
			}
			if writer != nil {
				t.Fatalf("a rejected configuration still produced a writer: %+v", writer)
			}
		})
	}
}

// TestMiddleware_CookieValueCannotInjectAResponseHeader: the session identifier
// written into a cookie comes from a token minter, but a caller can pass
// anything, and a value carrying CR LF would terminate the Set-Cookie header and
// begin a new one -- HTTP response splitting, CWE-113. The emitted response must
// carry exactly one cookie and none of the attacker's.
func TestMiddleware_CookieValueCannotInjectAResponseHeader(t *testing.T) {
	t.Parallel()

	writer, err := NewSecureCookieWriter(SecureCookieConfig{CookieName: "session_id"})
	if err != nil {
		t.Fatalf("NewSecureCookieWriter: %v", err)
	}

	hostile := "good\r\nSet-Cookie: admin=1\r\n\r\n<script>alert(1)</script>"

	rec := httptest.NewRecorder()
	writer.Write(rec, hostile)

	headers := rec.Header().Values("Set-Cookie")
	if len(headers) != 1 {
		t.Fatalf("emitted %d Set-Cookie headers, want 1: %v", len(headers), headers)
	}
	if strings.Contains(headers[0], "\r") || strings.Contains(headers[0], "\n") {
		t.Fatalf("the emitted header carries a line break: %q", headers[0])
	}

	// net/http drops the invalid bytes and quotes what remains, so the injected
	// text survives only as part of ONE cookie's value. What must not exist is a
	// second cookie: that would be an attribute or a header the attacker wrote.
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("response carries %d cookies, want 1: %v", len(cookies), cookies)
	}
	if cookies[0].Name != "session_id" {
		t.Fatalf("cookie name = %q, want session_id", cookies[0].Name)
	}
	for _, cookie := range cookies {
		if cookie.Name == "admin" {
			t.Fatalf("an injected cookie survived into the response: %v", cookie)
		}
	}
}

// ---------------------------------------------------------------------------
// Context keys
// ---------------------------------------------------------------------------

// TestMiddleware_ContextKeysDoNotCollideWithPlainStrings: context values are
// keyed by an interface, and a plain string "user_id" set by any other package
// in the process -- a logging middleware, a tracing library, a handler that
// stashed a form field -- would be indistinguishable from the authenticated
// principal if the key were a bare string. That is the collision Go's
// context.WithValue documentation warns about, and here it would be an
// authentication bypass: an unauthenticated request could carry its own
// "user_id" into a handler that trusts GetUserID.
//
// ContextKey is a defined type, so the two keys are different. Change UserIDKey
// and friends back to untyped string constants and every row fails.
func TestMiddleware_ContextKeysDoNotCollideWithPlainStrings(t *testing.T) {
	t.Parallel()

	claims := &authjwt.Claims{UserID: "attacker"}
	sessionData := &storage.SessionData{UserID: "attacker"}
	user := &storage.User{ID: "attacker"}

	tests := []struct {
		name   string
		key    string
		value  any
		lookup func(*http.Request) bool
	}{
		{
			name: "user_id", key: "user_id", value: "attacker",
			lookup: func(r *http.Request) bool { _, ok := GetUserID(r); return ok },
		},
		{
			name: "session_id", key: "session_id", value: "attacker-session",
			lookup: func(r *http.Request) bool { _, ok := GetSessionID(r); return ok },
		},
		{
			name: "session_data", key: "session_data", value: sessionData,
			lookup: func(r *http.Request) bool { _, ok := GetSessionData(r); return ok },
		},
		{
			name: "claims", key: "claims", value: claims,
			lookup: func(r *http.Request) bool { _, ok := GetClaims(r); return ok },
		},
		{
			name: "user", key: "user", value: user,
			lookup: func(r *http.Request) bool { _, ok := GetUser(r); return ok },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			//nolint:staticcheck,revive // A bare string key is exactly the hostile input under test.
			ctx := context.WithValue(context.Background(), tc.key, tc.value)
			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody).WithContext(ctx)

			if tc.lookup(req) {
				t.Fatalf("a plain string key %q was read as the authenticated %s", tc.key, tc.name)
			}
		})
	}

	// And the reverse: what the middleware stores must not be readable through a
	// bare string either, or another package could overwrite or exfiltrate it.
	ctx := WithUserID(WithSessionID(context.Background(), "s1"), "u1")
	//nolint:staticcheck,revive // Reading through a bare string key is the point.
	if got := ctx.Value("user_id"); got != nil {
		t.Fatalf("the authenticated user ID is readable through a plain string key: %v", got)
	}
	//nolint:staticcheck,revive // Reading through a bare string key is the point.
	if got := ctx.Value("session_id"); got != nil {
		t.Fatalf("the session ID is readable through a plain string key: %v", got)
	}
	if got, ok := GetUserID(&http.Request{}); ok {
		t.Fatalf("a request with no context values reported user %q", got)
	}
}

// TestMiddleware_TypeConfusionInContextValues: the accessors type-assert what
// they find. A value of the right key and the wrong type -- planted by another
// middleware that reused ContextKey, or by a handler storing a *storage.User
// where a string belongs -- must be reported as absent rather than panicking or
// being coerced.
func TestMiddleware_TypeConfusionInContextValues(t *testing.T) {
	t.Parallel()

	ctx := context.WithValue(context.Background(), UserIDKey, 42)
	ctx = context.WithValue(ctx, SessionIDKey, []byte("s1"))
	ctx = context.WithValue(ctx, ClaimsKey, "not-claims")
	ctx = context.WithValue(ctx, SessionDataKey, storage.SessionData{UserID: "by-value"})
	ctx = context.WithValue(ctx, UserKey, storage.User{ID: "by-value"})

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody).WithContext(ctx)

	if _, ok := GetUserID(req); ok {
		t.Error("a non-string user ID was accepted")
	}
	if _, ok := GetSessionID(req); ok {
		t.Error("a non-string session ID was accepted")
	}
	if _, ok := GetClaims(req); ok {
		t.Error("a non-Claims value was accepted as claims")
	}
	if _, ok := GetSessionData(req); ok {
		t.Error("a by-value SessionData was accepted where a pointer belongs")
	}
	if _, ok := GetUser(req); ok {
		t.Error("a by-value User was accepted where a pointer belongs")
	}
}
