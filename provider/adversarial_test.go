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
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authoidc "github.com/meysam81/go-auth/auth/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/linkedin"
	"golang.org/x/oauth2/microsoft"
	"golang.org/x/oauth2/slack"
)

// ---------------------------------------------------------------------------
// F-19 — authorized party on a multi-audience ID token
// ---------------------------------------------------------------------------

// TestOIDC_MultiAudienceWithoutMatchingAzpRejected drives the whole
// ExtractUserInfo path with tokens that are correctly signed, unexpired, and
// name this client in aud — everything oidc.IDTokenVerifier checks — and
// differ only in the authorized party.
//
// OpenID Connect Core 1.0 section 3.1.3.7 steps 4 and 5: aud must contain the
// client ID, azp MUST be present when aud holds more than one value, and azp
// MUST equal the client ID whenever it is present at all. "Listed in aud" is
// not "minted for us": a provider may issue one token to relying party B and
// name A alongside it, and without the azp check A accepts B's token as an
// authentication of the subject to A. Finding F-19, CWE-287.
//
// Reverting verifyAuthorizedParty to `return nil` leaves every rejection case
// here passing verification.
func TestOIDC_MultiAudienceWithoutMatchingAzpRejected(t *testing.T) {
	t.Parallel()

	idp := newHostileIDP(t)
	p := idp.provider(t)
	const attacker = "attacker-relying-party"

	tests := []struct {
		name    string
		claims  map[string]interface{}
		wantErr error
	}{
		{
			name:    "two audiences, azp names the other relying party",
			claims:  map[string]interface{}{"aud": []string{idp.clientID, attacker}, "azp": attacker},
			wantErr: ErrAuthorizedPartyMismatch,
		},
		{
			name:    "two audiences, azp omitted entirely",
			claims:  map[string]interface{}{"aud": []string{idp.clientID, attacker}},
			wantErr: ErrMissingAuthorizedParty,
		},
		{
			name:    "two audiences, azp is JSON null",
			claims:  map[string]interface{}{"aud": []string{idp.clientID, attacker}, "azp": nil},
			wantErr: ErrMissingAuthorizedParty,
		},
		{
			name:    "two audiences, azp is a number rather than a party name",
			claims:  map[string]interface{}{"aud": []string{idp.clientID, attacker}, "azp": 1234},
			wantErr: ErrMissingAuthorizedParty,
		},
		{
			name:    "two audiences, azp is an array containing the client ID",
			claims:  map[string]interface{}{"aud": []string{idp.clientID, attacker}, "azp": []string{idp.clientID}},
			wantErr: ErrMissingAuthorizedParty,
		},
		{
			name:    "two audiences, azp is the empty string",
			claims:  map[string]interface{}{"aud": []string{idp.clientID, attacker}, "azp": ""},
			wantErr: ErrMissingAuthorizedParty,
		},
		{
			name:    "azp differs from the client ID only by trailing whitespace",
			claims:  map[string]interface{}{"aud": []string{idp.clientID, attacker}, "azp": idp.clientID + " "},
			wantErr: ErrAuthorizedPartyMismatch,
		},
		{
			name:    "azp differs from the client ID only by case",
			claims:  map[string]interface{}{"aud": []string{idp.clientID, attacker}, "azp": strings.ToUpper(idp.clientID)},
			wantErr: ErrAuthorizedPartyMismatch,
		},
		{
			name:    "azp is a prefix of the client ID",
			claims:  map[string]interface{}{"aud": []string{idp.clientID, attacker}, "azp": idp.clientID[:len(idp.clientID)-1]},
			wantErr: ErrAuthorizedPartyMismatch,
		},
		{
			// A repeated audience is still a multi-valued aud on the wire.
			// The strict reading is deliberate: a token whose aud array can be
			// padded is a token whose azp requirement could otherwise be
			// suppressed by repetition.
			name:    "audience repeated twice with no azp",
			claims:  map[string]interface{}{"aud": []string{idp.clientID, idp.clientID}},
			wantErr: ErrMissingAuthorizedParty,
		},
		{
			name:    "single audience with a wrong azp is still refused",
			claims:  map[string]interface{}{"aud": []string{idp.clientID}, "azp": attacker},
			wantErr: ErrAuthorizedPartyMismatch,
		},
		{
			name:   "two audiences with an azp naming this client is accepted",
			claims: map[string]interface{}{"aud": []string{idp.clientID, attacker}, "azp": idp.clientID},
		},
		{
			name:   "single audience needs no azp",
			claims: map[string]interface{}{"aud": []string{idp.clientID}},
		},
		{
			// aud arrives as a bare JSON string rather than an array. The
			// audience is single-valued, so no azp is required: the shape of
			// the claim must not change the decision.
			name:   "single audience encoded as a JSON string needs no azp",
			claims: map[string]interface{}{"aud": idp.clientID},
		},
		{
			name:   "single audience with a matching azp is accepted",
			claims: map[string]interface{}{"aud": []string{idp.clientID}, "azp": idp.clientID},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			info, err := p.ExtractUserInfo(context.Background(), idp.idToken(t, tc.claims))
			assertUserInfoContract(t, info, err)

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ExtractUserInfo() error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ExtractUserInfo() error = %v, want the token accepted", err)
			}
			if info.Subject != hostileSubject {
				t.Fatalf("Subject = %q, want %q", info.Subject, hostileSubject)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ID token verification: issuer, signature, shape
// ---------------------------------------------------------------------------

// TestOIDC_ForeignIssuerTokenRejected mints a token with a real signature from
// the key this provider trusts, and changes only the iss claim.
//
// This is the identity-provider mix-up class described in RFC 9700 section
// 4.4: when the same relying party talks to more than one issuer, a token
// minted by issuer B and replayed at the endpoint expecting issuer A must be
// refused, otherwise a subject on the weaker issuer impersonates the same
// subject identifier on the stronger one. The control lives in
// oidc.Config.SkipIssuerCheck, which this package leaves off for every
// provider except Microsoft's deliberately-per-tenant common endpoint.
//
// The paired accept case is the evidence: the two tokens differ in nothing but
// iss, so a regression that stops checking the issuer turns a rejection into
// an acceptance rather than merely changing an error string.
func TestOIDC_ForeignIssuerTokenRejected(t *testing.T) {
	t.Parallel()

	idp := newHostileIDP(t)
	p := idp.provider(t)

	tests := []struct {
		name       string
		issuer     interface{}
		wantReject bool
	}{
		{name: "issuer of an unrelated provider", issuer: "https://evil.example", wantReject: true},
		{name: "issuer with a trailing slash appended", issuer: idp.server.URL + "/", wantReject: true},
		{name: "issuer with the scheme stripped", issuer: strings.TrimPrefix(idp.server.URL, "http://"), wantReject: true},
		{name: "issuer as the empty string", issuer: "", wantReject: true},
		{name: "issuer as a number", issuer: 42, wantReject: true},
		{name: "issuer as reported by discovery", issuer: idp.server.URL},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			info, err := p.ExtractUserInfo(context.Background(), idp.idToken(t, map[string]interface{}{"iss": tc.issuer}))
			assertUserInfoContract(t, info, err)

			if tc.wantReject {
				if err == nil {
					t.Fatalf("ExtractUserInfo() accepted a token issued by %v", tc.issuer)
				}
				return
			}
			if err != nil {
				t.Fatalf("ExtractUserInfo() error = %v, want the token accepted", err)
			}
		})
	}
}

// TestOIDC_ForgedOrMalformedIDTokenRejected covers the JWS-level attacks an
// unauthenticated caller can mount on the callback, since the raw id_token is
// entirely attacker-supplied at that point.
//
// The alg:none case is the classic unsecured-JWT acceptance described in RFC
// 8725 section 3.1 (and RFC 7519 section 6, which defines the "none" algorithm
// that a verifier must never accept for a token it relies on). The
// wrong-signer case is signature confusion: a token whose header names the kid
// the provider published but whose signature was produced by a key the
// attacker generated. The tampered-payload case re-encodes claims underneath a
// signature that was valid for different ones.
func TestOIDC_ForgedOrMalformedIDTokenRejected(t *testing.T) {
	t.Parallel()

	idp := newHostileIDP(t)
	p := idp.provider(t)

	attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	valid := idp.rawIDToken(t, nil)
	parts := strings.Split(valid, ".")
	if len(parts) != 3 {
		t.Fatalf("fixture token has %d segments, want 3", len(parts))
	}

	tamperedPayload := advB64(advMustJSON(t, map[string]interface{}{
		"iss": idp.server.URL,
		"aud": []string{idp.clientID},
		"sub": "somebody-else",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}))

	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "unsecured JWT with alg none and an empty signature",
			raw: idp.signWith(t, nil,
				map[string]string{"alg": "none", "typ": "JWT"},
				idp.baseClaims(nil)),
		},
		{
			name: "alg none carrying the signature bytes of a valid token",
			raw: strings.Join([]string{
				advB64(advMustJSON(t, map[string]string{"alg": "none", "typ": "JWT", "kid": hostileKeyID})),
				parts[1],
				parts[2],
			}, "."),
		},
		{
			name: "signed by a key the attacker generated under the published kid",
			raw:  idp.signWith(t, attackerKey, map[string]string{"alg": "RS256", "typ": "JWT", "kid": hostileKeyID}, idp.baseClaims(nil)),
		},
		{
			name: "signed by an attacker key under an unknown kid",
			raw:  idp.signWith(t, attackerKey, map[string]string{"alg": "RS256", "typ": "JWT", "kid": "../../etc/passwd"}, idp.baseClaims(nil)),
		},
		{
			name: "claims replaced underneath a signature made for other claims",
			raw:  parts[0] + "." + tamperedPayload + "." + parts[2],
		},
		{
			name: "signature segment truncated",
			raw:  parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-8],
		},
		{
			name: "signature segment removed",
			raw:  parts[0] + "." + parts[1],
		},
		{
			name: "payload is not JSON",
			raw:  parts[0] + "." + advB64([]byte("not json at all")) + "." + parts[2],
		},
		{
			name: "not a JWT at all",
			raw:  "................",
		},
		{
			name: "empty segments",
			raw:  "..",
		},
		{
			name: "expired an hour ago",
			raw:  idp.rawIDToken(t, map[string]interface{}{"exp": time.Now().Add(-time.Hour).Unix()}),
		},
		{
			name: "not valid before an hour from now",
			raw:  idp.rawIDToken(t, map[string]interface{}{"nbf": time.Now().Add(time.Hour).Unix()}),
		},
		{
			name: "audience omits this client",
			raw:  idp.rawIDToken(t, map[string]interface{}{"aud": []string{"attacker-relying-party"}}),
		},
		{
			name: "audience is an empty array",
			raw:  idp.rawIDToken(t, map[string]interface{}{"aud": []string{}}),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			info, err := p.ExtractUserInfo(context.Background(), advTokenWithID(tc.raw))
			assertUserInfoContract(t, info, err)
			if err == nil {
				t.Fatal("ExtractUserInfo() accepted a token it must refuse")
			}
		})
	}
}

// TestOIDC_TokenResponseWithoutUsableIDToken covers the OIDC provider handed a
// token response that carries no signed assertion: an access token alone says
// who may call an API, never who authenticated. Treating one as proof of
// authentication is the token-substitution class in the security
// considerations of OpenID Connect Core 1.0 — the ID token is the only part of
// the response bound to a subject by a signature.
//
// The type-confusion rows matter because Extra() returns interface{} straight
// out of the provider's JSON: a provider that emits id_token as a number, an
// object or a bool must land on ErrNoIDToken rather than on a type assertion
// that was written without its comma-ok.
func TestOIDC_TokenResponseWithoutUsableIDToken(t *testing.T) {
	t.Parallel()

	idp := newHostileIDP(t)
	p := idp.provider(t)

	tests := []struct {
		name  string
		token *oauth2.Token
	}{
		{name: "nil token", token: nil},
		{name: "access token only", token: &oauth2.Token{AccessToken: "opaque", TokenType: "Bearer"}},
		{name: "id_token present but empty", token: advTokenWithID("")},
		{
			name: "id_token is a number",
			token: (&oauth2.Token{AccessToken: "a"}).
				WithExtra(map[string]interface{}{"id_token": float64(1)}),
		},
		{
			name: "id_token is a bool",
			token: (&oauth2.Token{AccessToken: "a"}).
				WithExtra(map[string]interface{}{"id_token": true}),
		},
		{
			name: "id_token is an object",
			token: (&oauth2.Token{AccessToken: "a"}).
				WithExtra(map[string]interface{}{"id_token": map[string]interface{}{"jwt": "x"}}),
		},
		{
			name: "id_token is JSON null",
			token: (&oauth2.Token{AccessToken: "a"}).
				WithExtra(map[string]interface{}{"id_token": nil}),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			info, err := p.ExtractUserInfo(context.Background(), tc.token)
			assertUserInfoContract(t, info, err)
			if !errors.Is(err, ErrNoIDToken) {
				t.Fatalf("ExtractUserInfo() error = %v, want %v", err, ErrNoIDToken)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// F-20 — a hostile user-info response
// ---------------------------------------------------------------------------

// TestOAuth2_UserInfoBodyCapAtTheBoundary pins the exact edge of the
// [MaxUserInfoBytes] bound rather than only the runaway case: one byte over
// must be refused and exactly the limit must still be served, because an
// off-by-one in the io.LimitReader headroom breaks a legitimate provider while
// an absent bound is the memory-exhaustion primitive of finding F-20 (CWE-400,
// the decompression/oversized-payload denial-of-service class).
//
// The transport is deliberately unbounded so nothing but ExtractUserInfo's own
// LimitReader can stop the read.
func TestOAuth2_UserInfoBodyCapAtTheBoundary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		size    int64
		wantErr error
	}{
		{name: "exactly the limit is served", size: MaxUserInfoBytes},
		{name: "one byte over the limit is refused", size: MaxUserInfoBytes + 1, wantErr: ErrUserInfoTooLarge},
		{name: "four times the limit is refused", size: 4 * MaxUserInfoBytes, wantErr: ErrUserInfoTooLarge},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := advJSONServer(t, http.StatusOK, paddedUserInfo(t, tc.size))
			p := NewOAuth2ProviderWithClient("fake", advOAuth2Config(srv.URL), srv.URL,
				requireIDExtractor, srv.Client())

			info, err := p.ExtractUserInfo(context.Background(), advStaticToken())
			assertUserInfoContract(t, info, err)

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ExtractUserInfo() error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ExtractUserInfo() error = %v, want a body of exactly the limit to be served", err)
			}
			if info.Subject != "u-1" {
				t.Fatalf("Subject = %q, want %q", info.Subject, "u-1")
			}
		})
	}
}

// TestOAuth2_NonOKUserInfoErrorDoesNotEmbedTheBody covers the log-amplification
// half of the same class: a provider that answers a user-info call with a
// non-200 and a megabyte of body must produce an error naming the status, not
// an error carrying the body. The error string is what reaches a log line, and
// a log line is not a place to put an attacker-controlled megabyte
// (CWE-532/CWE-400).
//
// It also pins that the status decision beats the parse: a 401 whose body is a
// perfectly well-formed user document must not authenticate anybody.
func TestOAuth2_NonOKUserInfoErrorDoesNotEmbedTheBody(t *testing.T) {
	t.Parallel()

	marker := strings.Repeat("SECRETPADDING", 4096) // ~53 KB, far past the snippet bound

	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "unauthorized with a huge body", status: http.StatusUnauthorized, body: marker},
		{name: "forbidden with a huge body", status: http.StatusForbidden, body: marker},
		{name: "server error with a huge body", status: http.StatusInternalServerError, body: marker},
		{name: "too many requests with a huge body", status: http.StatusTooManyRequests, body: marker},
		{
			name:   "a valid user document behind a 401 authenticates nobody",
			status: http.StatusUnauthorized,
			body:   `{"id":"u-1","email":"jo@example.com"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := advJSONServer(t, tc.status, tc.body)
			p := NewOAuth2ProviderWithClient("fake", advOAuth2Config(srv.URL), srv.URL,
				requireIDExtractor, srv.Client())

			info, err := p.ExtractUserInfo(context.Background(), advStaticToken())
			assertUserInfoContract(t, info, err)
			if err == nil {
				t.Fatalf("ExtractUserInfo() accepted a %d response", tc.status)
			}
			if len(err.Error()) > userInfoErrorSnippetBytes*2 {
				t.Fatalf("error is %d bytes: the response body was not bounded", len(err.Error()))
			}
			if strings.Count(err.Error(), "SECRETPADDING") > userInfoErrorSnippetBytes {
				t.Fatal("error embedded the whole response body")
			}
		})
	}
}

// TestOAuth2_MalformedUserInfoBodyRejected feeds ExtractUserInfo the bodies a
// hostile or broken provider actually emits behind an HTTP 200: truncated
// JSON, a bare literal, an array where the contract says object, HTML from an
// intercepting proxy, and a nesting depth intended to exhaust the decoder's
// stack (the deeply-nested-JSON denial-of-service class, CWE-674).
//
// Every one of them must produce an error and no user. The JSON-null row is
// the sharpest: it decodes without error into a nil map, so the only thing
// standing between it and a subject-less "authenticated" user is the
// extractor's refusal plus the ErrNoUserInfo guard.
func TestOAuth2_MalformedUserInfoBodyRejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{name: "empty body", body: ""},
		{name: "whitespace only", body: "   \n\t "},
		{name: "truncated object", body: `{"id":`},
		{name: "unterminated string", body: `{"id":"u-1`},
		{name: "trailing garbage after a valid object", body: `{"id":"u-1"}<script>`},
		{name: "JSON null decodes to a nil map", body: `null`},
		{name: "JSON array where an object is expected", body: `[{"id":"u-1"}]`},
		{name: "empty JSON array", body: `[]`},
		{name: "bare JSON string", body: `"u-1"`},
		{name: "bare JSON number", body: `12345`},
		{name: "bare JSON bool", body: `true`},
		{name: "HTML from an intercepting proxy", body: `<html><body>login required</body></html>`},
		{name: "NUL bytes", body: "\x00\x00\x00\x00"},
		{name: "deeply nested arrays", body: strings.Repeat("[", 20000) + strings.Repeat("]", 20000)},
		{name: "unbalanced deep nesting", body: strings.Repeat("{\"a\":", 20000)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := advJSONServer(t, http.StatusOK, tc.body)
			p := NewOAuth2ProviderWithClient("fake", advOAuth2Config(srv.URL), srv.URL,
				requireIDExtractor, srv.Client())

			info, err := p.ExtractUserInfo(context.Background(), advStaticToken())
			assertUserInfoContract(t, info, err)
			if err == nil {
				t.Fatalf("ExtractUserInfo() accepted body %q", advTruncate(tc.body))
			}
		})
	}
}

// TestOAuth2_DeclinedExtractionNeverReturnsNilNil pins the contract that makes
// the caller's `info.Subject` safe: an extract function that declines a
// response must surface as [ErrNoUserInfo], never as a nil *UserInfo beside a
// nil error. The (nil, nil) return is a nil-pointer dereference one frame up —
// in an OIDC callback handler, which is reachable by an unauthenticated
// attacker, so the panic is a denial of service rather than a bug report.
//
// The extractor here returns nil for every input, so removing the guard in
// ExtractUserInfo makes every row return (nil, nil) and the deref in
// assertUserInfoContract panics.
func TestOAuth2_DeclinedExtractionNeverReturnsNilNil(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{name: "application level failure inside a 200", body: `{"ok":false,"error":"invalid_auth"}`},
		{name: "empty object", body: `{}`},
		{name: "object of nulls", body: `{"id":null,"sub":null,"email":null}`},
		{name: "object the extractor does not recognize", body: `{"unexpected":"shape"}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := advJSONServer(t, http.StatusOK, tc.body)
			p := NewOAuth2ProviderWithClient("fake", advOAuth2Config(srv.URL), srv.URL,
				func(map[string]interface{}) *authoidc.UserInfo { return nil }, srv.Client())

			info, err := p.ExtractUserInfo(context.Background(), advStaticToken())
			assertUserInfoContract(t, info, err)
			if !errors.Is(err, ErrNoUserInfo) {
				t.Fatalf("ExtractUserInfo() error = %v, want %v", err, ErrNoUserInfo)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The OAuth2-only vendor parsers
// ---------------------------------------------------------------------------

// TestVendorExtractors_TypeConfusedPayloadsDoNotPanic runs each OAuth2-only
// vendor parser against a realistic payload and then against payloads where
// every field is absent or of the wrong JSON type.
//
// These parsers read an untyped map[string]interface{} decoded straight from a
// remote body, so each field access is a type assertion on attacker-influenced
// data. A single assertion written without its comma-ok panics the handler
// goroutine, which for net/http means the request dies and, for a panic in a
// goroutine the handler spawned, the process does. That is CWE-704 turning
// into CWE-248 on an unauthenticated path.
//
// The contract asserted for every row: no panic, no (nil, nil), and a
// declined response reported as [ErrNoUserInfo] rather than as a user with an
// empty subject — an empty subject is an identity that collides with every
// other empty subject.
func TestVendorExtractors_TypeConfusedPayloadsDoNotPanic(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		build func() *OAuth2Provider
		body  string
		want  *authoidc.UserInfo // nil means the response must be declined
	}{
		// --- GitHub: id is a JSON number, everything else optional ---
		{
			name:  "github realistic payload",
			build: func() *OAuth2Provider { return NewGitHubProvider("id", "secret", "https://rp.example/cb") },
			body: `{"id":583231,"login":"octocat","name":"The Octocat",` +
				`"email":"octocat@github.com","avatar_url":"https://avatars.example/583231"}`,
			want: &authoidc.UserInfo{
				Subject: "583231", Username: "octocat", Name: "The Octocat",
				Email: "octocat@github.com", EmailVerified: true,
				Picture: "https://avatars.example/583231",
			},
		},
		{
			name:  "github every field missing",
			build: func() *OAuth2Provider { return NewGitHubProvider("id", "secret", "https://rp.example/cb") },
			body:  `{}`,
		},
		{
			name:  "github id as a string",
			build: func() *OAuth2Provider { return NewGitHubProvider("id", "secret", "https://rp.example/cb") },
			body:  `{"id":"583231","login":"octocat"}`,
		},
		{
			name:  "github id as a bool",
			build: func() *OAuth2Provider { return NewGitHubProvider("id", "secret", "https://rp.example/cb") },
			body:  `{"id":true}`,
		},
		{
			name:  "github id as an object",
			build: func() *OAuth2Provider { return NewGitHubProvider("id", "secret", "https://rp.example/cb") },
			body:  `{"id":{"value":1}}`,
		},
		{
			name:  "github every other field of the wrong type",
			build: func() *OAuth2Provider { return NewGitHubProvider("id", "secret", "https://rp.example/cb") },
			body:  `{"id":1,"login":42,"name":["a"],"email":{"a":1},"avatar_url":false}`,
			want:  &authoidc.UserInfo{Subject: "1"},
		},
		{
			name:  "github email present as an empty string is not a verified address",
			build: func() *OAuth2Provider { return NewGitHubProvider("id", "secret", "https://rp.example/cb") },
			body:  `{"id":1,"email":""}`,
			want:  &authoidc.UserInfo{Subject: "1"},
		},

		// --- Discord: id is a snowflake *string* ---
		{
			name:  "discord realistic payload",
			build: func() *OAuth2Provider { return NewDiscordProvider("id", "secret", "https://rp.example/cb") },
			body: `{"id":"80351110224678912","username":"nelly","global_name":"Nelly",` +
				`"avatar":"8342729096ea3675442027381ff50dfe","verified":true,"email":"nelly@example.com"}`,
			want: &authoidc.UserInfo{
				Subject: "80351110224678912", Username: "nelly", Name: "Nelly",
				Email: "nelly@example.com", EmailVerified: true,
				Picture: "https://cdn.discordapp.com/avatars/80351110224678912/8342729096ea3675442027381ff50dfe.png",
			},
		},
		{
			name:  "discord every field missing",
			build: func() *OAuth2Provider { return NewDiscordProvider("id", "secret", "https://rp.example/cb") },
			body:  `{}`,
		},
		{
			name:  "discord id as a number loses precision and is refused",
			build: func() *OAuth2Provider { return NewDiscordProvider("id", "secret", "https://rp.example/cb") },
			body:  `{"id":80351110224678912,"username":"nelly"}`,
		},
		{
			name:  "discord id as an empty string",
			build: func() *OAuth2Provider { return NewDiscordProvider("id", "secret", "https://rp.example/cb") },
			body:  `{"id":"","username":"nelly"}`,
		},
		{
			name:  "discord every other field of the wrong type",
			build: func() *OAuth2Provider { return NewDiscordProvider("id", "secret", "https://rp.example/cb") },
			body:  `{"id":"1","username":null,"global_name":[],"avatar":{},"verified":"true","email":7}`,
			want:  &authoidc.UserInfo{Subject: "1"},
		},
		{
			name:  "discord verified string does not assert a verified address",
			build: func() *OAuth2Provider { return NewDiscordProvider("id", "secret", "https://rp.example/cb") },
			body:  `{"id":"1","email":"nelly@example.com","verified":"true"}`,
			want:  &authoidc.UserInfo{Subject: "1", Email: "nelly@example.com"},
		},
		{
			name:  "discord falls back to username when global_name is absent",
			build: func() *OAuth2Provider { return NewDiscordProvider("id", "secret", "https://rp.example/cb") },
			body:  `{"id":"1","username":"nelly"}`,
			want:  &authoidc.UserInfo{Subject: "1", Username: "nelly", Name: "nelly"},
		},

		// --- LinkedIn: OIDC-shaped userinfo document over plain OAuth2 ---
		{
			name:  "linkedin realistic payload",
			build: func() *OAuth2Provider { return NewLinkedInProvider("id", "secret", "https://rp.example/cb") },
			body: `{"sub":"782bbtaQ","email":"jo@example.com","email_verified":true,"name":"Jo Doe",` +
				`"given_name":"Jo","family_name":"Doe","picture":"https://media.example/jo"}`,
			want: &authoidc.UserInfo{
				Subject: "782bbtaQ", Email: "jo@example.com", EmailVerified: true,
				Name: "Jo Doe", Username: "jo.doe", Picture: "https://media.example/jo",
			},
		},
		{
			name:  "linkedin every field missing",
			build: func() *OAuth2Provider { return NewLinkedInProvider("id", "secret", "https://rp.example/cb") },
			body:  `{}`,
		},
		{
			name:  "linkedin sub as a number",
			build: func() *OAuth2Provider { return NewLinkedInProvider("id", "secret", "https://rp.example/cb") },
			body:  `{"sub":782}`,
		},
		{
			name:  "linkedin sub as an empty string",
			build: func() *OAuth2Provider { return NewLinkedInProvider("id", "secret", "https://rp.example/cb") },
			body:  `{"sub":""}`,
		},
		{
			name:  "linkedin every other field of the wrong type",
			build: func() *OAuth2Provider { return NewLinkedInProvider("id", "secret", "https://rp.example/cb") },
			body: `{"sub":"s","email":[],"email_verified":"true","name":1,` +
				`"picture":{"url":"x"},"given_name":2,"family_name":3}`,
			want: &authoidc.UserInfo{Subject: "s"},
		},
		{
			name:  "linkedin half a name yields no username",
			build: func() *OAuth2Provider { return NewLinkedInProvider("id", "secret", "https://rp.example/cb") },
			body:  `{"sub":"s","given_name":"Jo"}`,
			want:  &authoidc.UserInfo{Subject: "s"},
		},

		// --- Slack: nested user object behind an ok flag ---
		{
			name:  "slack realistic payload",
			build: func() *OAuth2Provider { return NewSlackProvider("id", "secret", "https://rp.example/cb") },
			body: `{"ok":true,"user":{"id":"U0G9QF9C6","name":"Sonny","email":"sonny@example.com",` +
				`"image_192":"https://slack.example/192.png","image_512":"https://slack.example/512.png"},` +
				`"team":{"id":"T0G9PQBBK"}}`,
			want: &authoidc.UserInfo{
				Subject: "U0G9QF9C6", Name: "Sonny", Username: "Sonny",
				Email: "sonny@example.com", EmailVerified: true,
				Picture: "https://slack.example/512.png",
			},
		},
		{
			name:  "slack every field missing",
			build: func() *OAuth2Provider { return NewSlackProvider("id", "secret", "https://rp.example/cb") },
			body:  `{}`,
		},
		{
			name:  "slack ok as a string",
			build: func() *OAuth2Provider { return NewSlackProvider("id", "secret", "https://rp.example/cb") },
			body:  `{"ok":"true","user":{"id":"U1","name":"Sonny"}}`,
		},
		{
			name:  "slack ok true with no user object",
			build: func() *OAuth2Provider { return NewSlackProvider("id", "secret", "https://rp.example/cb") },
			body:  `{"ok":true}`,
		},
		{
			name:  "slack user as an array",
			build: func() *OAuth2Provider { return NewSlackProvider("id", "secret", "https://rp.example/cb") },
			body:  `{"ok":true,"user":[{"id":"U1"}]}`,
		},
		{
			name:  "slack user as a string",
			build: func() *OAuth2Provider { return NewSlackProvider("id", "secret", "https://rp.example/cb") },
			body:  `{"ok":true,"user":"U1"}`,
		},
		{
			name:  "slack user id as a number",
			build: func() *OAuth2Provider { return NewSlackProvider("id", "secret", "https://rp.example/cb") },
			body:  `{"ok":true,"user":{"id":1234}}`,
		},
		{
			name:  "slack every other field of the wrong type",
			build: func() *OAuth2Provider { return NewSlackProvider("id", "secret", "https://rp.example/cb") },
			body:  `{"ok":true,"user":{"id":"U1","name":42,"email":[],"image_512":7,"image_192":null}}`,
			want:  &authoidc.UserInfo{Subject: "U1"},
		},
		{
			name:  "slack empty email is not a verified address",
			build: func() *OAuth2Provider { return NewSlackProvider("id", "secret", "https://rp.example/cb") },
			body:  `{"ok":true,"user":{"id":"U1","email":""}}`,
			want:  &authoidc.UserInfo{Subject: "U1"},
		},
		{
			name:  "slack falls back to the 192px avatar",
			build: func() *OAuth2Provider { return NewSlackProvider("id", "secret", "https://rp.example/cb") },
			body:  `{"ok":true,"user":{"id":"U1","image_192":"https://slack.example/192.png"}}`,
			want:  &authoidc.UserInfo{Subject: "U1", Picture: "https://slack.example/192.png"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := advJSONServer(t, http.StatusOK, tc.body)
			p := tc.build()
			// Redirect the vendor provider at the fake endpoint without
			// touching its parser, which is the thing under test.
			p.userInfoURL = srv.URL
			p.httpClient = srv.Client()

			info, err := p.ExtractUserInfo(context.Background(), advStaticToken())
			assertUserInfoContract(t, info, err)

			if tc.want == nil {
				if !errors.Is(err, ErrNoUserInfo) {
					t.Fatalf("ExtractUserInfo() error = %v, want %v", err, ErrNoUserInfo)
				}
				return
			}
			if err != nil {
				t.Fatalf("ExtractUserInfo() error = %v, want a user", err)
			}
			assertUserInfoEqual(t, info, tc.want)
			if info.RawClaims == nil {
				t.Error("RawClaims = nil, want the decoded response preserved")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Vendor configuration
// ---------------------------------------------------------------------------

// TestVendorConstructors_OAuth2EndpointsAndScopesPinned freezes the endpoints,
// scopes and user-info URLs the package documentation promises for the four
// OAuth2-only providers.
//
// It is a rot detector, and the rot is a security event rather than a cosmetic
// one: a token URL that silently moves — through a dependency bump of
// golang.org/x/oauth2, or an edit to a vendor file — sends a client secret and
// an authorization code to whatever host now sits behind the old name, and a
// user-info URL that moves turns an authentication into an unauthenticated
// 404 body that some parser then has to decline. A scope that quietly grows is
// consent the user was never asked for.
func TestVendorConstructors_OAuth2EndpointsAndScopesPinned(t *testing.T) {
	t.Parallel()

	const (
		clientID    = "client-id"
		secret      = "client-secret"
		redirectURL = "https://rp.example/cb"
	)

	tests := []struct {
		name        string
		provider    *OAuth2Provider
		wantName    string
		wantAuthURL string
		// wantExchangeURL is the OAuth2 token endpoint. It avoids the word
		// "token" in the field name so gosec G101 does not read a table of
		// published URLs as a table of credentials.
		wantExchangeURL string
		wantUserInfo    string
		wantScopes      []string
	}{
		{
			name:            "github",
			provider:        NewGitHubProvider(clientID, secret, redirectURL),
			wantName:        "github",
			wantAuthURL:     "https://github.com/login/oauth/authorize",
			wantExchangeURL: "https://github.com/login/oauth/access_token",
			wantUserInfo:    "https://api.github.com/user",
			wantScopes:      []string{"user:email", "read:user"},
		},
		{
			name:            "discord",
			provider:        NewDiscordProvider(clientID, secret, redirectURL),
			wantName:        "discord",
			wantAuthURL:     "https://discord.com/api/oauth2/authorize",
			wantExchangeURL: "https://discord.com/api/oauth2/token",
			wantUserInfo:    "https://discord.com/api/users/@me",
			wantScopes:      []string{"identify", "email"},
		},
		{
			name:            "linkedin",
			provider:        NewLinkedInProvider(clientID, secret, redirectURL),
			wantName:        "linkedin",
			wantAuthURL:     "https://www.linkedin.com/oauth/v2/authorization",
			wantExchangeURL: "https://www.linkedin.com/oauth/v2/accessToken",
			wantUserInfo:    "https://api.linkedin.com/v2/userinfo",
			wantScopes:      []string{"openid", "profile", "email"},
		},
		{
			name:            "slack",
			provider:        NewSlackProvider(clientID, secret, redirectURL),
			wantName:        "slack",
			wantAuthURL:     "https://slack.com/oauth/authorize",
			wantExchangeURL: "https://slack.com/api/oauth.access",
			wantUserInfo:    "https://slack.com/api/users.identity",
			wantScopes:      []string{"identity.basic", "identity.email", "identity.avatar"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := tc.provider
			if p.Name() != tc.wantName {
				t.Errorf("Name() = %q, want %q", p.Name(), tc.wantName)
			}
			if p.GetOIDCProvider() != nil {
				t.Error("GetOIDCProvider() is non-nil: an OAuth2-only provider issues no ID token")
			}

			cfg := p.GetOAuth2Config()
			if cfg.Endpoint.AuthURL != tc.wantAuthURL {
				t.Errorf("AuthURL = %q, want %q", cfg.Endpoint.AuthURL, tc.wantAuthURL)
			}
			if cfg.Endpoint.TokenURL != tc.wantExchangeURL {
				t.Errorf("TokenURL = %q, want %q", cfg.Endpoint.TokenURL, tc.wantExchangeURL)
			}
			if p.userInfoURL != tc.wantUserInfo {
				t.Errorf("userInfoURL = %q, want %q", p.userInfoURL, tc.wantUserInfo)
			}
			if strings.Join(cfg.Scopes, " ") != strings.Join(tc.wantScopes, " ") {
				t.Errorf("Scopes = %v, want %v", cfg.Scopes, tc.wantScopes)
			}
			if cfg.ClientID != clientID || cfg.ClientSecret != secret || cfg.RedirectURL != redirectURL {
				t.Errorf("constructor did not wire the credentials through: %+v", cfg)
			}
			for _, u := range []string{cfg.Endpoint.AuthURL, cfg.Endpoint.TokenURL, p.userInfoURL} {
				if !strings.HasPrefix(u, "https://") {
					t.Errorf("endpoint %q is not https: a bearer token would cross the network in clear", u)
				}
			}
		})
	}
}

// TestVendorConstructors_OIDCIssuerAndScopesPinned freezes, for every OIDC
// vendor constructor, the exact URL discovery is fetched from and the scopes
// and endpoints the resulting provider is configured with.
//
// The discovery URL is the security-relevant half. It is the address that
// yields the issuer identifier, the token endpoint and the JWKS URI, so
// whoever answers it decides which keys sign the assertions this library
// believes. A constructor whose issuer constant rots — or is edited to a host
// somebody else controls — hands that decision away, and nothing downstream
// can detect it. Finding F-20 (CWE-918) is the same property seen from the
// other side.
//
// Discovery is served from an in-process stub rather than the real vendors:
// this test asserts what the library asks for, not what the vendors answer.
//
// It does not call t.Parallel: it swaps the package-level default HTTP client
// for the duration, and Go resumes parallel tests only after every sequential
// test has finished, so nothing else observes the swap.
func TestVendorConstructors_OIDCIssuerAndScopesPinned(t *testing.T) {
	standardScopes := []string{"openid", "profile", "email"}

	tests := []struct {
		name             string
		build            func(context.Context) (*BaseOIDCProvider, error)
		reportedIssuer   string
		wantName         string
		wantDiscoveryURL string
		wantAuthURL      string
		// wantExchangeURL is the OAuth2 token endpoint. It avoids the word
		// "token" in the field name so gosec G101 does not read a table of
		// published URLs as a table of credentials.
		wantExchangeURL string
		wantScopes      []string
	}{
		{
			name: "google",
			build: func(ctx context.Context) (*BaseOIDCProvider, error) {
				return NewGoogleProvider(ctx, "cid", "secret", "https://rp.example/cb")
			},
			reportedIssuer:   "https://accounts.google.com",
			wantName:         "google",
			wantDiscoveryURL: "https://accounts.google.com/.well-known/openid-configuration",
			wantAuthURL:      "https://accounts.google.com/o/oauth2/auth",
			wantExchangeURL:  "https://oauth2.googleapis.com/token",
			wantScopes:       standardScopes,
		},
		{
			name: "apple",
			build: func(ctx context.Context) (*BaseOIDCProvider, error) {
				return NewAppleProvider(ctx, "cid", "secret", "https://rp.example/cb")
			},
			reportedIssuer:   "https://appleid.apple.com",
			wantName:         "apple",
			wantDiscoveryURL: "https://appleid.apple.com/.well-known/openid-configuration",
			wantAuthURL:      "https://appleid.apple.com/auth/authorize",
			wantExchangeURL:  "https://appleid.apple.com/auth/token",
			wantScopes:       []string{"openid", "email", "name"},
		},
		{
			name: "gitlab",
			build: func(ctx context.Context) (*BaseOIDCProvider, error) {
				return NewGitLabProvider(ctx, "cid", "secret", "https://rp.example/cb")
			},
			reportedIssuer:   "https://gitlab.com",
			wantName:         "gitlab",
			wantDiscoveryURL: "https://gitlab.com/.well-known/openid-configuration",
			wantAuthURL:      "https://gitlab.com/oauth/authorize",
			wantExchangeURL:  "https://gitlab.com/oauth/token",
			wantScopes:       standardScopes,
		},
		{
			// The common endpoint reports a templated issuer, so discovery is
			// fetched from one URL while the issuer is declared separately.
			// Pinning both is what stops the pair from drifting into an
			// accidental SkipIssuerCheck against a concrete issuer.
			name: "microsoft common tenant",
			build: func(ctx context.Context) (*BaseOIDCProvider, error) {
				return NewMicrosoftProvider(ctx, "cid", "secret", "https://rp.example/cb")
			},
			reportedIssuer:   "https://login.microsoftonline.com/{tenantid}/v2.0",
			wantName:         "microsoft",
			wantDiscoveryURL: "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
			wantAuthURL:      "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
			wantExchangeURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/token",
			wantScopes:       standardScopes,
		},
		{
			name: "okta",
			build: func(ctx context.Context) (*BaseOIDCProvider, error) {
				return NewOktaProvider(ctx, "tenant.okta.example", "cid", "secret", "https://rp.example/cb")
			},
			reportedIssuer:   "https://tenant.okta.example/oauth2/default",
			wantName:         "okta",
			wantDiscoveryURL: "https://tenant.okta.example/oauth2/default/.well-known/openid-configuration",
			wantAuthURL:      "https://tenant.okta.example/oauth2/default/v1/authorize",
			wantExchangeURL:  "https://tenant.okta.example/oauth2/default/v1/token",
			wantScopes:       standardScopes,
		},
		{
			// Auth0's issuer carries a trailing slash and go-oidc compares the
			// discovery document's issuer byte for byte, so the slash is part
			// of the contract rather than cosmetic.
			name: "auth0",
			build: func(ctx context.Context) (*BaseOIDCProvider, error) {
				return NewAuth0Provider(ctx, "tenant.eu.auth0.example", "cid", "secret", "https://rp.example/cb")
			},
			reportedIssuer:   "https://tenant.eu.auth0.example/",
			wantName:         "auth0",
			wantDiscoveryURL: "https://tenant.eu.auth0.example/.well-known/openid-configuration",
			wantAuthURL:      "https://tenant.eu.auth0.example/authorize",
			wantExchangeURL:  "https://tenant.eu.auth0.example/oauth/token",
			wantScopes:       standardScopes,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stub := &discoveryStub{
				issuer:   tc.reportedIssuer,
				authURL:  tc.wantAuthURL,
				tokenURL: tc.wantExchangeURL,
			}
			stubDefaultHTTPClient(t, &http.Client{Transport: stub})

			p, err := tc.build(context.Background())
			if err != nil {
				t.Fatalf("constructor error = %v", err)
			}
			if len(stub.requested) != 1 {
				t.Fatalf("discovery fetched %d URLs (%v), want exactly 1", len(stub.requested), stub.requested)
			}
			if stub.requested[0] != tc.wantDiscoveryURL {
				t.Errorf("discovery URL = %q, want %q", stub.requested[0], tc.wantDiscoveryURL)
			}
			if p.Name() != tc.wantName {
				t.Errorf("Name() = %q, want %q", p.Name(), tc.wantName)
			}

			cfg := p.GetOAuth2Config()
			if cfg.Endpoint.AuthURL != tc.wantAuthURL {
				t.Errorf("AuthURL = %q, want %q", cfg.Endpoint.AuthURL, tc.wantAuthURL)
			}
			if cfg.Endpoint.TokenURL != tc.wantExchangeURL {
				t.Errorf("TokenURL = %q, want %q", cfg.Endpoint.TokenURL, tc.wantExchangeURL)
			}
			if strings.Join(cfg.Scopes, " ") != strings.Join(tc.wantScopes, " ") {
				t.Errorf("Scopes = %v, want %v", cfg.Scopes, tc.wantScopes)
			}
			if cfg.Scopes[0] != "openid" {
				t.Errorf("Scopes = %v, want openid first: without it the provider issues no ID token", cfg.Scopes)
			}
			if p.HTTPClient() == nil || p.HTTPClient() == http.DefaultClient {
				t.Error("HTTPClient() left discovery and JWKS on the unbounded default client (F-20)")
			}
			for _, u := range []string{tc.wantDiscoveryURL, cfg.Endpoint.AuthURL, cfg.Endpoint.TokenURL} {
				if !strings.HasPrefix(u, "https://") {
					t.Errorf("endpoint %q is not https", u)
				}
			}
		})
	}
}

// TestVendorConstructors_UpstreamEndpointConstantsPinned freezes the
// golang.org/x/oauth2 endpoint values the vendor constructors delegate to, so
// a dependency bump that moves an authorization or token URL is caught here
// rather than in production traffic. The vendor constructors read these at
// call time, so the constants are as load-bearing as the code around them.
func TestVendorConstructors_UpstreamEndpointConstantsPinned(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		got               oauth2.Endpoint
		wantAuth, wantTok string
	}{
		{"github", github.Endpoint, "https://github.com/login/oauth/authorize", "https://github.com/login/oauth/access_token"},
		{"linkedin", linkedin.Endpoint, "https://www.linkedin.com/oauth/v2/authorization", "https://www.linkedin.com/oauth/v2/accessToken"},
		{"slack", slack.Endpoint, "https://slack.com/oauth/authorize", "https://slack.com/api/oauth.access"},
		{
			"microsoft common", microsoft.AzureADEndpoint("common"),
			"https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
			"https://login.microsoftonline.com/common/oauth2/v2.0/token",
		},
		{"discord", discordEndpoint, "https://discord.com/api/oauth2/authorize", "https://discord.com/api/oauth2/token"},
		{"apple", appleEndpoint, "https://appleid.apple.com/auth/authorize", "https://appleid.apple.com/auth/token"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.got.AuthURL != tc.wantAuth {
				t.Errorf("AuthURL = %q, want %q", tc.got.AuthURL, tc.wantAuth)
			}
			if tc.got.TokenURL != tc.wantTok {
				t.Errorf("TokenURL = %q, want %q", tc.got.TokenURL, tc.wantTok)
			}
		})
	}
}

// TestOIDCConstructor_MisconfigurationRefusedBeforeAnyRequest pins that a
// provider which cannot enforce its own checks is refused at construction
// instead of at the first sign-in.
//
// The empty client ID is the security-relevant row: oidc.IDTokenVerifier
// treats an empty ClientID as a configuration error only when
// SkipClientIDCheck is unset, and verifyAuthorizedParty comparing azp against
// "" would accept any token carrying azp:"". A misconfiguration that disarms
// an authorization check must fail loudly at startup (F-19).
//
// Each case must also fail without a network request: an issuer URL that is
// never fetched is an SSRF that never happens (F-20).
func TestOIDCConstructor_MisconfigurationRefusedBeforeAnyRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		pname     string
		issuerURL string
		clientID  string
	}{
		{name: "no provider name", pname: "", issuerURL: "https://idp.example", clientID: "cid"},
		{name: "no issuer URL", pname: "p", issuerURL: "", clientID: "cid"},
		{name: "no client ID", pname: "p", issuerURL: "https://idp.example", clientID: ""},
		{name: "nothing at all", pname: "", issuerURL: "", clientID: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			counting := &refusingTransport{t: t}
			p, err := NewOIDCProviderWithClient(context.Background(), &http.Client{Transport: counting},
				tc.pname, tc.issuerURL, tc.clientID, "secret", "https://rp.example/cb", []string{"openid"})
			if !errors.Is(err, ErrProviderMisconfigured) {
				t.Fatalf("constructor error = %v, want %v", err, ErrProviderMisconfigured)
			}
			if p != nil {
				t.Fatal("constructor returned a provider alongside an error")
			}
			if counting.calls != 0 {
				t.Fatalf("constructor issued %d HTTP requests before validating its arguments", counting.calls)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

const (
	hostileKeyID   = "hostile-idp-key"
	hostileSubject = "subject-under-test"
)

// assertUserInfoContract is the invariant every ExtractUserInfo call must
// satisfy: exactly one of a user and an error, and never the (nil, nil) pair
// that nil-panics the caller. The Subject read is deliberate — it is the
// dereference a callback handler performs, so this helper panics exactly where
// the caller would.
func assertUserInfoContract(t *testing.T, info *authoidc.UserInfo, err error) {
	t.Helper()
	if err != nil {
		if info != nil {
			t.Fatalf("ExtractUserInfo() returned user info %+v alongside error %v", info, err)
		}
		return
	}
	if info == nil {
		t.Fatal("ExtractUserInfo() returned (nil, nil): the caller dereferences this")
	}
	_ = info.Subject
}

func assertUserInfoEqual(t *testing.T, got, want *authoidc.UserInfo) {
	t.Helper()
	if got.Subject != want.Subject {
		t.Errorf("Subject = %q, want %q", got.Subject, want.Subject)
	}
	if got.Email != want.Email {
		t.Errorf("Email = %q, want %q", got.Email, want.Email)
	}
	if got.EmailVerified != want.EmailVerified {
		t.Errorf("EmailVerified = %v, want %v", got.EmailVerified, want.EmailVerified)
	}
	if got.Name != want.Name {
		t.Errorf("Name = %q, want %q", got.Name, want.Name)
	}
	if got.Username != want.Username {
		t.Errorf("Username = %q, want %q", got.Username, want.Username)
	}
	if got.Picture != want.Picture {
		t.Errorf("Picture = %q, want %q", got.Picture, want.Picture)
	}
}

// requireIDExtractor is a minimally realistic extract function: it declines any
// response that does not name a subject, which is what every vendor parser in
// this package does.
func requireIDExtractor(data map[string]interface{}) *authoidc.UserInfo {
	id, ok := data["id"].(string)
	if !ok || id == "" {
		return nil
	}
	return &authoidc.UserInfo{Subject: id, RawClaims: data}
}

func advJSONServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		// A short write is the client having stopped reading, which is the
		// expected end of an over-long response rather than a test failure.
		if _, err := io.WriteString(w, body); err != nil {
			return
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func advOAuth2Config(base string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Endpoint:     oauth2.Endpoint{AuthURL: base + "/authorize", TokenURL: base + "/token"},
	}
}

// advStaticToken is a non-expiring token, so golang.org/x/oauth2 makes the
// user info request as-is instead of trying to refresh first.
func advStaticToken() *oauth2.Token {
	return &oauth2.Token{AccessToken: "access-token", TokenType: "Bearer"}
}

func advTokenWithID(raw string) *oauth2.Token {
	return (&oauth2.Token{AccessToken: "access-token", TokenType: "Bearer"}).
		WithExtra(map[string]interface{}{"id_token": raw})
}

// paddedUserInfo builds a syntactically valid user info document of exactly
// size bytes, so a test can sit on either side of the byte limit.
func paddedUserInfo(t *testing.T, size int64) string {
	t.Helper()
	const prefix = `{"id":"u-1","pad":"`
	const suffix = `"}`
	pad := size - int64(len(prefix)) - int64(len(suffix))
	if pad < 0 {
		t.Fatalf("size %d is too small to hold a document", size)
	}
	body := prefix + strings.Repeat("a", int(pad)) + suffix
	if int64(len(body)) != size {
		t.Fatalf("built a %d byte body, want %d", len(body), size)
	}
	return body
}

func advTruncate(s string) string {
	if len(s) <= 64 {
		return s
	}
	return s[:64] + "..."
}

// refusingTransport fails the test if a request is ever made through it.
type refusingTransport struct {
	t     *testing.T
	calls int
}

func (r *refusingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.calls++
	r.t.Errorf("unexpected HTTP request to %s", req.URL)
	return nil, errors.New("no network in tests")
}

// discoveryStub answers exactly one OIDC discovery document, in process, and
// records the URL it was asked for. It exists so a vendor constructor can be
// exercised without reaching the real provider.
type discoveryStub struct {
	issuer    string
	authURL   string
	tokenURL  string
	requested []string
}

func (d *discoveryStub) RoundTrip(req *http.Request) (*http.Response, error) {
	d.requested = append(d.requested, req.URL.String())

	doc, err := json.Marshal(map[string]interface{}{
		"issuer":                                d.issuer,
		"authorization_endpoint":                d.authURL,
		"token_endpoint":                        d.tokenURL,
		"jwks_uri":                              strings.TrimSuffix(d.issuer, "/") + "/keys",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
	if err != nil {
		return nil, err
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(string(doc))),
		Request:    req,
	}, nil
}

// stubDefaultHTTPClient swaps the package-level bounded client a constructor
// falls back to, and restores it when the test ends. Callers must not run in
// parallel: Go resumes parallel tests only once every sequential test has
// finished, which is what keeps this swap invisible to them.
func stubDefaultHTTPClient(t *testing.T, c *http.Client) {
	t.Helper()
	previous := defaultHTTPClient
	defaultHTTPClient = func() *http.Client { return c }
	t.Cleanup(func() { defaultHTTPClient = previous })
}

// hostileIDP is a minimal OpenID provider under the test's control: a
// discovery document, a JWKS, and the ability to mint an ID token with any
// header, any claim set and any signing key.
type hostileIDP struct {
	server   *httptest.Server
	key      *rsa.PrivateKey
	clientID string
}

func newHostileIDP(t *testing.T) *hostileIDP {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	idp := &hostileIDP{key: key, clientID: "relying-party-under-test"}

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
				"kid": hostileKeyID,
				"use": "sig",
				"alg": "RS256",
				"n":   advB64(key.N.Bytes()),
				"e":   advB64(big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	})

	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

func (h *hostileIDP) writeJSON(t *testing.T, w http.ResponseWriter, doc map[string]interface{}) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(doc); err != nil {
		t.Errorf("encode test document: %v", err)
	}
}

// provider builds a BaseOIDCProvider pointed at this IdP, reachable only
// through the test server's own client.
func (h *hostileIDP) provider(t *testing.T) *BaseOIDCProvider {
	t.Helper()
	p, err := NewOIDCProviderWithClient(context.Background(), h.server.Client(),
		"hostile", h.server.URL, h.clientID, "secret", "https://rp.example/cb", []string{"openid"})
	if err != nil {
		t.Fatalf("NewOIDCProviderWithClient() error = %v", err)
	}
	return p
}

// baseClaims is a claim set that verifies, with overrides applied on top so a
// test states only the part it is attacking.
func (h *hostileIDP) baseClaims(overrides map[string]interface{}) map[string]interface{} {
	now := time.Now()
	claims := map[string]interface{}{
		"iss":            h.server.URL,
		"aud":            []string{h.clientID},
		"sub":            hostileSubject,
		"exp":            now.Add(time.Hour).Unix(),
		"iat":            now.Unix(),
		"nonce":          "nonce-value",
		"email":          "jo@example.com",
		"email_verified": true,
	}
	for k, v := range overrides {
		claims[k] = v
	}
	return claims
}

// signWith produces a compact JWS with the given header and claims. A nil key
// yields an empty signature, which is how an alg:none token is written.
func (h *hostileIDP) signWith(t *testing.T, key *rsa.PrivateKey, header map[string]string, claims map[string]interface{}) string {
	t.Helper()

	signingInput := advB64(advMustJSON(t, header)) + "." + advB64(advMustJSON(t, claims))
	if key == nil {
		return signingInput + "."
	}

	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15() error = %v", err)
	}
	return signingInput + "." + advB64(sig)
}

func (h *hostileIDP) rawIDToken(t *testing.T, overrides map[string]interface{}) string {
	t.Helper()
	return h.signWith(t, h.key,
		map[string]string{"alg": "RS256", "typ": "JWT", "kid": hostileKeyID},
		h.baseClaims(overrides))
}

func (h *hostileIDP) idToken(t *testing.T, overrides map[string]interface{}) *oauth2.Token {
	t.Helper()
	return advTokenWithID(h.rawIDToken(t, overrides))
}

func advMustJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return out
}

func advB64(in []byte) string { return base64.RawURLEncoding.EncodeToString(in) }
