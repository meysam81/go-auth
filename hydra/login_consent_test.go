package hydra_test

import (
	"context"
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

	"github.com/meysam81/go-auth/v2/hydra"
)

// seen is one request the admin double received.
type seen struct{ Method, Path, Query, ContentType, Body string }

// admin is a Hydra admin API double: it records each request and answers
// status, header and body.
func admin(t *testing.T, status int, header http.Header, body string) (*hydra.Client, *seen, *atomic.Int32) {
	t.Helper()
	got := &seen{}
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		*got = seen{r.Method, r.URL.EscapedPath(), r.URL.RawQuery, r.Header.Get("Content-Type"), string(b)}
		for k, v := range header {
			w.Header()[k] = v
		}
		w.WriteHeader(status)
		if _, err := io.WriteString(w, body); err != nil {
			t.Errorf("write: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := hydra.New(hydra.Config{AdminURL: srv.URL, HTTPClient: &http.Client{Timeout: 5 * time.Second}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, got, &hits
}

const created = "2026-11-14T10:00:00Z"

var client1 = hydra.OAuthClient{
	ClientID: "c1", ClientName: "App", RedirectURIs: []string{"http://127.0.0.1:33418/callback"},
	GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"},
	Scope: "read", TokenEndpointAuthMethod: "none", CreatedAt: time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC),
}

const client1JSON = `{"client_id":"c1","client_name":"App","redirect_uris":["http://127.0.0.1:33418/callback"],` +
	`"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"scope":"read",` +
	`"token_endpoint_auth_method":"none","created_at":"` + created + `","metadata":{}}`

type call func(context.Context, *hydra.Client) (any, error)

// requestCase is one admin call: what it sends and what it decodes.
type requestCase struct {
	name                      string
	call                      call
	status                    int
	header                    http.Header
	answer                    string
	method, path, query, body string
	want                      any
}

func runRequestCases(t *testing.T, tests []requestCase) {
	t.Helper()
	for i := range tests {
		tt := &tests[i]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, got, _ := admin(t, tt.status, tt.header, tt.answer)
			res, err := tt.call(t.Context(), c)
			if err != nil {
				t.Fatalf("call: %v", err)
			}
			wantType := ""
			if tt.body != "" {
				wantType = "application/json"
			}
			if want := (seen{tt.method, tt.path, tt.query, wantType, tt.body}); *got != want {
				t.Fatalf("request =\n%+v\nwant\n%+v", *got, want)
			}
			if !reflect.DeepEqual(res, tt.want) {
				t.Fatalf("result =\n%+v\nwant\n%+v", res, tt.want)
			}
		})
	}
}

const redirectJSON = `{"redirect_to":"https://auth.example.test/oauth2/auth?login_verifier=v"}`
const redirectTo = "https://auth.example.test/oauth2/auth?login_verifier=v"

func TestClient_LoginAndConsentRequests(t *testing.T) {
	t.Parallel()
	ext, err := json.Marshal(struct {
		Grant string `json:"grant"`
	}{"g1"})
	if err != nil {
		t.Fatal(err)
	}
	runRequestCases(t, []requestCase{
		{
			name: "get login request", status: http.StatusOK,
			call: func(ctx context.Context, c *hydra.Client) (any, error) { return c.LoginRequest(ctx, "lc 1") },
			answer: `{"challenge":"lc 1","skip":false,"subject":"","request_url":"https://auth.example.test/oauth2/auth?x=1",` +
				`"requested_scope":["read"],"session_id":"s1","client":` + client1JSON + `}`,
			method: http.MethodGet, path: "/admin/oauth2/auth/requests/login", query: "login_challenge=lc+1",
			want: hydra.LoginRequest{Challenge: "lc 1", RequestURL: "https://auth.example.test/oauth2/auth?x=1",
				RequestedScope: []string{"read"}, SessionID: "s1", Client: client1},
		},
		{
			name: "accept login", status: http.StatusOK, answer: redirectJSON,
			call: func(ctx context.Context, c *hydra.Client) (any, error) {
				return c.AcceptLogin(ctx, "lc1", hydra.AcceptLogin{Subject: "u1", AMR: []string{"pwd", "otp"}})
			},
			method: http.MethodPut, path: "/admin/oauth2/auth/requests/login/accept", query: "login_challenge=lc1",
			body: `{"subject":"u1","remember":false,"amr":["pwd","otp"]}`, want: redirectTo,
		},
		{
			name: "reject login", status: http.StatusOK, answer: redirectJSON,
			call: func(ctx context.Context, c *hydra.Client) (any, error) {
				return c.RejectLogin(ctx, "lc1", hydra.Reject{Error: "access_denied", ErrorDescription: "Sign-in was refused."})
			},
			method: http.MethodPut, path: "/admin/oauth2/auth/requests/login/reject", query: "login_challenge=lc1",
			body: `{"error":"access_denied","error_description":"Sign-in was refused."}`, want: redirectTo,
		},
		{
			name: "get consent request", status: http.StatusOK,
			call: func(ctx context.Context, c *hydra.Client) (any, error) { return c.ConsentRequest(ctx, "cc1") },
			answer: `{"challenge":"cc1","consent_request_id":"cr1","skip":false,"subject":"u1","request_url":"https://auth.example.test/oauth2/auth?y=2",` +
				`"requested_scope":["read","offline_access"],"requested_access_token_audience":[],` +
				`"login_challenge":"lc1","client":` + client1JSON + `}`,
			method: http.MethodGet, path: "/admin/oauth2/auth/requests/consent", query: "consent_challenge=cc1",
			want: hydra.ConsentRequest{Challenge: "cc1", ConsentRequestID: "cr1", Subject: "u1", RequestURL: "https://auth.example.test/oauth2/auth?y=2",
				RequestedScope: []string{"read", "offline_access"}, RequestedAudience: []string{}, LoginChallenge: "lc1", Client: client1},
		},
		{
			name: "accept consent with access-token claims", status: http.StatusOK, answer: redirectJSON,
			call: func(ctx context.Context, c *hydra.Client) (any, error) {
				return c.AcceptConsent(ctx, "cc1", hydra.AcceptConsent{GrantScope: []string{"read"},
					Session: hydra.ConsentSession{AccessToken: ext}})
			},
			method: http.MethodPut, path: "/admin/oauth2/auth/requests/consent/accept", query: "consent_challenge=cc1",
			body: `{"grant_scope":["read"],"remember":false,"session":{"access_token":{"grant":"g1"}}}`, want: redirectTo,
		},
		{
			name: "reject consent", status: http.StatusOK, answer: redirectJSON,
			call: func(ctx context.Context, c *hydra.Client) (any, error) {
				return c.RejectConsent(ctx, "cc1", hydra.Reject{Error: "access_denied"})
			},
			method: http.MethodPut, path: "/admin/oauth2/auth/requests/consent/reject", query: "consent_challenge=cc1",
			body: `{"error":"access_denied"}`, want: redirectTo,
		},
	})
}

// An unknown, expired or answered challenge is one sentinel whatever Hydra's
// status: the browser is answered alike in every case. An empty challenge is
// refused before any request.
func TestClient_ChallengeFailures(t *testing.T) {
	t.Parallel()
	calls := map[string]func(context.Context, *hydra.Client, string) error{
		"login": func(ctx context.Context, c *hydra.Client, ch string) error {
			_, err := c.LoginRequest(ctx, ch)
			return err
		},
		"accept login": func(ctx context.Context, c *hydra.Client, ch string) error {
			_, err := c.AcceptLogin(ctx, ch, hydra.AcceptLogin{Subject: "u1"})
			return err
		},
		"reject login": func(ctx context.Context, c *hydra.Client, ch string) error {
			_, err := c.RejectLogin(ctx, ch, hydra.Reject{Error: "access_denied"})
			return err
		},
		"consent": func(ctx context.Context, c *hydra.Client, ch string) error {
			_, err := c.ConsentRequest(ctx, ch)
			return err
		},
		"accept consent": func(ctx context.Context, c *hydra.Client, ch string) error {
			_, err := c.AcceptConsent(ctx, ch, hydra.AcceptConsent{})
			return err
		},
		"reject consent": func(ctx context.Context, c *hydra.Client, ch string) error {
			_, err := c.RejectConsent(ctx, ch, hydra.Reject{Error: "access_denied"})
			return err
		},
	}
	for name, do := range calls {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for status, want := range map[int]bool{404: true, 409: true, 410: true, 500: false, 400: false} {
				c, _, _ := admin(t, status, nil, `{"error":"x"}`)
				if err := do(t.Context(), c, "ch1"); err == nil || errors.Is(err, hydra.ErrInvalidChallenge) != want {
					t.Errorf("status %d: err = %v, want ErrInvalidChallenge %v", status, err, want)
				}
			}
			c, _, hits := admin(t, http.StatusOK, nil, redirectJSON)
			if err := do(t.Context(), c, ""); !errors.Is(err, hydra.ErrInvalidChallenge) || hits.Load() != 0 {
				t.Errorf("empty challenge: err = %v after %d requests", err, hits.Load())
			}
		})
	}
}

// A 2xx answer without redirect_to, a redirect, an oversized or malformed
// body all fail and match no sentinel.
func TestClient_InfrastructureFailures(t *testing.T) {
	t.Parallel()
	accept := func(ctx context.Context, c *hydra.Client) error {
		_, err := c.AcceptLogin(ctx, "lc1", hydra.AcceptLogin{Subject: "u1"})
		return err
	}
	tests := map[string]struct {
		status int
		header http.Header
		body   string
	}{
		"no redirect_to": {http.StatusOK, nil, `{}`},
		"redirect":       {http.StatusTemporaryRedirect, http.Header{"Location": {"https://elsewhere.example.test/"}}, ``},
		"oversize":       {http.StatusOK, nil, redirectJSON + strings.Repeat(" ", 1<<20)},
		"not json":       {http.StatusOK, nil, `<html>`},
	}
	for name, tt := range tests {
		c, _, _ := admin(t, tt.status, tt.header, tt.body)
		if err := accept(t.Context(), c); err == nil || errors.Is(err, hydra.ErrInvalidChallenge) {
			t.Errorf("%s: err = %v, want an error matching no sentinel", name, err)
		}
	}
}

func TestClient_RefusesBadAnswersBeforeSending(t *testing.T) {
	t.Parallel()
	c, _, hits := admin(t, http.StatusOK, nil, redirectJSON)
	ctx := t.Context()
	for name, err := range map[string]error{
		"accept login without a subject":  second(c.AcceptLogin(ctx, "lc1", hydra.AcceptLogin{})),
		"reject login without an error":   second(c.RejectLogin(ctx, "lc1", hydra.Reject{})),
		"reject consent without an error": second(c.RejectConsent(ctx, "cc1", hydra.Reject{})),
		"session claims not an object": second(c.AcceptConsent(ctx, "cc1",
			hydra.AcceptConsent{Session: hydra.ConsentSession{AccessToken: json.RawMessage(`["x"]`)}})),
	} {
		if err == nil || errors.Is(err, hydra.ErrInvalidChallenge) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("%d requests sent", hits.Load())
	}
}

func second[T any](_ T, err error) error { return err }

func TestNew_Refuses(t *testing.T) {
	t.Parallel()
	for name, cfg := range map[string]hydra.Config{
		"no client":     {AdminURL: "http://hydra-admin:4445"},
		"no timeout":    {AdminURL: "http://hydra-admin:4445", HTTPClient: &http.Client{}},
		"no URL":        {HTTPClient: &http.Client{Timeout: time.Second}},
		"URL has query": {AdminURL: "http://hydra-admin:4445?x=1", HTTPClient: &http.Client{Timeout: time.Second}},
	} {
		if _, err := hydra.New(cfg); err == nil {
			t.Errorf("%s: New accepted it", name)
		}
	}
}
