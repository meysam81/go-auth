package oauthrs_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/meysam81/go-auth/v2/oauthrs"
)

const issuer = "https://auth.example.test"

var t0 = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// answerJSON is an introspection response as Hydra writes it.
type answerJSON struct {
	Active   any             `json:"active"`
	TokenUse string          `json:"token_use,omitempty"`
	ClientID string          `json:"client_id,omitempty"`
	Subject  string          `json:"sub,omitempty"`
	Issuer   string          `json:"iss,omitempty"`
	Exp      int64           `json:"exp,omitempty"`
	Iat      int64           `json:"iat,omitempty"`
	Scope    string          `json:"scope,omitempty"`
	Aud      json.RawMessage `json:"aud,omitempty"`
	Ext      json.RawMessage `json:"ext,omitempty"`
}

// answer is an access token valid for an hour after t0; edit tweaks it.
func answer(edit func(*answerJSON)) string {
	a := answerJSON{
		Active: true, TokenUse: "access_token", ClientID: "client-1", Subject: "subject-1", Issuer: issuer,
		Exp: t0.Add(time.Hour).Unix(), Iat: t0.Unix(), Scope: "read domains:add",
		Aud: json.RawMessage(`[]`), Ext: json.RawMessage(`{"grant":"g1"}`),
	}
	if edit != nil {
		edit(&a)
	}
	b, err := json.Marshal(a)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// hydra is an introspection endpoint double that counts its calls.
func hydra(t *testing.T, h http.HandlerFunc) (string, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/admin/oauth2/introspect", &hits
}

func respond(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if _, err := w.Write([]byte(body)); err != nil {
			panic(err)
		}
	}
}

func introspector(t *testing.T, endpoint string, edit func(*oauthrs.IntrospectorConfig)) *oauthrs.Introspector {
	t.Helper()
	cfg := oauthrs.IntrospectorConfig{
		Endpoint: endpoint, Issuer: issuer, HTTPClient: &http.Client{Timeout: 5 * time.Second},
		Now: func() time.Time { return t0 },
	}
	if edit != nil {
		edit(&cfg)
	}
	in, err := oauthrs.NewIntrospector(cfg)
	if err != nil {
		t.Fatalf("NewIntrospector: %v", err)
	}
	return in
}

// An endpoint that omits iat leaves IssuedAt the zero time, not 1970.
func TestIntrospector_AbsentIatIsTheZeroTime(t *testing.T) {
	t.Parallel()
	endpoint, _ := hydra(t, respond(http.StatusOK, answer(func(a *answerJSON) { a.Iat = 0 })))
	got, err := introspector(t, endpoint, nil).Verify(t.Context(), "tok")
	if err != nil || !got.IssuedAt.IsZero() {
		t.Fatalf("IssuedAt = %v, err %v; want the zero time", got.IssuedAt, err)
	}
}

func TestIntrospector_VerifiesAnActiveAccessToken(t *testing.T) {
	t.Parallel()
	endpoint, _ := hydra(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		if r.Method != http.MethodPost || r.URL.Path != "/admin/oauth2/introspect" ||
			r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" ||
			r.PostForm.Encode() != "token=ory_at_tok" || r.Header.Get("Authorization") != "" {
			t.Errorf("request %s %s %q form %q", r.Method, r.URL.Path, r.Header.Get("Content-Type"), r.PostForm.Encode())
		}
		respond(http.StatusOK, answer(nil))(w, r)
	})
	got, err := introspector(t, endpoint, nil).Verify(t.Context(), "ory_at_tok")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	want := oauthrs.Token{
		Subject: "subject-1", ClientID: "client-1", Issuer: issuer, TokenUse: "access_token",
		Scopes: []string{"read", "domains:add"}, Audience: []string{},
		ExpiresAt: time.Unix(t0.Add(time.Hour).Unix(), 0), IssuedAt: time.Unix(t0.Unix(), 0),
		Ext: json.RawMessage(`{"grant":"g1"}`),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Verify =\n%+v\nwant\n%+v", got, want)
	}
	if !got.HasScopes("read") || got.HasScopes("read", "admin") {
		t.Fatal("HasScopes disagrees with Scopes")
	}
}

func TestIntrospector_AudienceStringOrArray(t *testing.T) {
	t.Parallel()
	for raw, want := range map[string][]string{`"a"`: {"a"}, `["a","b"]`: {"a", "b"}, `null`: nil} {
		endpoint, _ := hydra(t, respond(http.StatusOK, answer(func(a *answerJSON) { a.Aud = json.RawMessage(raw) })))
		got, err := introspector(t, endpoint, nil).Verify(t.Context(), "tok")
		if err != nil || !reflect.DeepEqual(got.Audience, want) {
			t.Errorf("aud %s: Audience = %#v, %v; want %#v", raw, got.Audience, err, want)
		}
	}
}

// F-02 and RFC 7662 section 2.2: only an active access token from the issuer
// passes. Hydra answers a refresh token active:true with token_use
// refresh_token, so a refresh token presented as a bearer must be refused
// here, not by each caller. With the cache on, a refusal is never cached.
func TestIntrospector_RefusesWhatIsNotAnActiveAccessToken(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"inactive":       `{"active":false}`,
		"refresh token":  answer(func(a *answerJSON) { a.TokenUse = "refresh_token" }),
		"no token_use":   answer(func(a *answerJSON) { a.TokenUse = "" }),
		"another issuer": answer(func(a *answerJSON) { a.Issuer = "https://evil.example.test" }),
		"no subject":     answer(func(a *answerJSON) { a.Subject = "" }),
		"no client":      answer(func(a *answerJSON) { a.ClientID = "" }),
		"no expiry":      answer(func(a *answerJSON) { a.Exp = 0 }),
		"expires now":    answer(func(a *answerJSON) { a.Exp = t0.Unix() }),
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			endpoint, hits := hydra(t, respond(http.StatusOK, body))
			in := introspector(t, endpoint, func(c *oauthrs.IntrospectorConfig) { c.CacheTTL = 30 * time.Second })
			for range 2 {
				tok, err := in.Verify(t.Context(), "tok")
				if !errors.Is(err, oauthrs.ErrInvalidToken) || !reflect.DeepEqual(tok, oauthrs.Token{}) {
					t.Fatalf("Verify = %+v, %v; want ErrInvalidToken", tok, err)
				}
			}
			if hits.Load() != 2 {
				t.Fatalf("endpoint hit %d times, want 2: a refusal must not be cached", hits.Load())
			}
		})
	}
}

// An endpoint that is down, slow, redirected or oversized is a server
// failure, never a refused token: it matches no sentinel.
func TestIntrospector_InfrastructureFailuresMatchNoSentinel(t *testing.T) {
	t.Parallel()
	var elsewhere atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere.Add(1)
		respond(http.StatusOK, answer(nil))(w, r)
	}))
	t.Cleanup(other.Close)
	tests := map[string]http.HandlerFunc{
		"500": respond(http.StatusInternalServerError, `{"error":"x"}`),
		"401": respond(http.StatusUnauthorized, `{"error":"x"}`),
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
		},
		"oversize":           respond(http.StatusOK, answer(nil)+strings.Repeat(" ", 64<<10)),
		"not json":           respond(http.StatusOK, `<html>`),
		"active is a string": respond(http.StatusOK, answer(func(a *answerJSON) { a.Active = "true" })),
		// The server sees the client hang up only once the body is read.
		"timeout": func(_ http.ResponseWriter, r *http.Request) {
			if _, err := io.Copy(io.Discard, r.Body); err == nil {
				<-r.Context().Done()
			}
		},
	}
	for name, h := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			endpoint, _ := hydra(t, h)
			in := introspector(t, endpoint, func(c *oauthrs.IntrospectorConfig) {
				c.HTTPClient = &http.Client{Timeout: 200 * time.Millisecond}
			})
			_, err := in.Verify(t.Context(), "tok")
			if err == nil || errors.Is(err, oauthrs.ErrInvalidToken) || strings.Contains(err.Error(), "tok") {
				t.Fatalf("Verify err = %v; want an error matching no sentinel and not naming the token", err)
			}
		})
	}
	if elsewhere.Load() != 0 {
		t.Fatalf("the redirect target was hit %d times", elsewhere.Load())
	}
}

func TestIntrospector_RefusesAMalformedTokenWithoutARequest(t *testing.T) {
	t.Parallel()
	endpoint, hits := hydra(t, respond(http.StatusOK, answer(nil)))
	in := introspector(t, endpoint, nil)
	for _, tok := range []string{"", "a b", strings.Repeat("a", 4097)} {
		if _, err := in.Verify(t.Context(), tok); !errors.Is(err, oauthrs.ErrInvalidToken) {
			t.Errorf("Verify(%.8q) = %v, want ErrInvalidToken", tok, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("endpoint hit %d times", hits.Load())
	}
}

func TestNewIntrospector_Refuses(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*oauthrs.IntrospectorConfig){
		"no client":            func(c *oauthrs.IntrospectorConfig) { c.HTTPClient = nil },
		"client with no limit": func(c *oauthrs.IntrospectorConfig) { c.HTTPClient = &http.Client{} },
		"no endpoint":          func(c *oauthrs.IntrospectorConfig) { c.Endpoint = "" },
		"relative endpoint":    func(c *oauthrs.IntrospectorConfig) { c.Endpoint = "/admin/oauth2/introspect" },
		"no issuer":            func(c *oauthrs.IntrospectorConfig) { c.Issuer = "" },
		"negative cache TTL":   func(c *oauthrs.IntrospectorConfig) { c.CacheTTL = -time.Second },
		"cache TTL over 60 s":  func(c *oauthrs.IntrospectorConfig) { c.CacheTTL = 61 * time.Second },
		"negative cache size":  func(c *oauthrs.IntrospectorConfig) { c.CacheTTL, c.CacheSize = time.Second, -1 },
		"cache size too large": func(c *oauthrs.IntrospectorConfig) { c.CacheTTL, c.CacheSize = time.Second, 1<<20+1 },
	}
	for name, edit := range tests {
		cfg := oauthrs.IntrospectorConfig{Endpoint: "http://hydra:4445/admin/oauth2/introspect", Issuer: issuer,
			HTTPClient: &http.Client{Timeout: time.Second}}
		edit(&cfg)
		if _, err := oauthrs.NewIntrospector(cfg); err == nil {
			t.Errorf("%s: NewIntrospector accepted it", name)
		}
	}
}
