package hydra_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/meysam81/go-auth/v2/hydra"
)

func TestClient_SessionAndClientRequests(t *testing.T) {
	t.Parallel()
	none := func(err error) (any, error) { return nil, err }
	next := http.Header{"Link": {`</admin/clients?page_size=250&page_token=t2>; rel="next", ` +
		`</admin/clients?page_size=250&page_token=t0>; rel="first"`}}
	runRequestCases(t, []requestCase{
		{
			name: "revoke one consent", status: http.StatusNoContent,
			call: func(ctx context.Context, c *hydra.Client) (any, error) {
				return none(c.RevokeConsentSessions(ctx, hydra.RevokeConsent{ConsentRequestID: "cr1"}))
			},
			method: http.MethodDelete, path: "/admin/oauth2/auth/sessions/consent", query: "consent_request_id=cr1",
		},
		{
			name: "revoke a subject's consent for a client", status: http.StatusNoContent,
			call: func(ctx context.Context, c *hydra.Client) (any, error) {
				return none(c.RevokeConsentSessions(ctx, hydra.RevokeConsent{Subject: "u1", Client: "c1"}))
			},
			method: http.MethodDelete, path: "/admin/oauth2/auth/sessions/consent", query: "client=c1&subject=u1",
		},
		{
			name: "revoke all of a subject's consent", status: http.StatusNoContent,
			call: func(ctx context.Context, c *hydra.Client) (any, error) {
				return none(c.RevokeConsentSessions(ctx, hydra.RevokeConsent{Subject: "u1", All: true}))
			},
			method: http.MethodDelete, path: "/admin/oauth2/auth/sessions/consent", query: "all=true&subject=u1",
		},
		{
			name: "end a subject's login sessions", status: http.StatusNoContent,
			call: func(ctx context.Context, c *hydra.Client) (any, error) {
				return none(c.RevokeLoginSessions(ctx, hydra.RevokeLogin{Subject: "u1"}))
			},
			method: http.MethodDelete, path: "/admin/oauth2/auth/sessions/login", query: "subject=u1",
		},
		{
			name: "end one login session", status: http.StatusNoContent,
			call: func(ctx context.Context, c *hydra.Client) (any, error) {
				return none(c.RevokeLoginSessions(ctx, hydra.RevokeLogin{SessionID: "sid1"}))
			},
			method: http.MethodDelete, path: "/admin/oauth2/auth/sessions/login", query: "sid=sid1",
		},
		{
			name: "list the first page of clients", status: http.StatusOK, header: next, answer: `[` + client1JSON + `]`,
			call:   func(ctx context.Context, c *hydra.Client) (any, error) { return c.ListClients(ctx, "") },
			method: http.MethodGet, path: "/admin/clients",
			want: hydra.ClientPage{Clients: []hydra.OAuthClient{client1}, NextPageToken: "t2"},
		},
		{
			name: "list the last page of clients", status: http.StatusOK, answer: `[]`,
			call:   func(ctx context.Context, c *hydra.Client) (any, error) { return c.ListClients(ctx, "t2") },
			method: http.MethodGet, path: "/admin/clients", query: "page_token=t2",
			want: hydra.ClientPage{Clients: []hydra.OAuthClient{}},
		},
		{
			name: "delete a client, escaping its id", status: http.StatusNoContent,
			call:   func(ctx context.Context, c *hydra.Client) (any, error) { return none(c.DeleteClient(ctx, "c/1")) },
			method: http.MethodDelete, path: "/admin/clients/c%2F1",
		},
		{
			name: "delete a client that is already gone", status: http.StatusNotFound, answer: `{"error":"Not Found"}`,
			call:   func(ctx context.Context, c *hydra.Client) (any, error) { return none(c.DeleteClient(ctx, "c1")) },
			method: http.MethodDelete, path: "/admin/clients/c1",
		},
	})
}

// A filter that could match nothing, or more than the caller named, is
// refused before any request; a failed admin call matches no sentinel.
func TestClient_SessionAndClientRefusals(t *testing.T) {
	t.Parallel()
	c, _, hits := admin(t, http.StatusNoContent, nil, ``)
	ctx := t.Context()
	for name, err := range map[string]error{
		"empty consent filter":          c.RevokeConsentSessions(ctx, hydra.RevokeConsent{}),
		"consent id beside a subject":   c.RevokeConsentSessions(ctx, hydra.RevokeConsent{ConsentRequestID: "cr1", Subject: "u1"}),
		"subject with neither":          c.RevokeConsentSessions(ctx, hydra.RevokeConsent{Subject: "u1"}),
		"subject with client and all":   c.RevokeConsentSessions(ctx, hydra.RevokeConsent{Subject: "u1", Client: "c1", All: true}),
		"client without a subject":      c.RevokeConsentSessions(ctx, hydra.RevokeConsent{Client: "c1"}),
		"empty login filter":            c.RevokeLoginSessions(ctx, hydra.RevokeLogin{}),
		"subject and session id":        c.RevokeLoginSessions(ctx, hydra.RevokeLogin{Subject: "u1", SessionID: "sid1"}),
		"empty client id":               c.DeleteClient(ctx, ""),
		"client id that walks the path": c.DeleteClient(ctx, ".."),
		"client id of one dot":          c.DeleteClient(ctx, "."),
	} {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("%d requests sent", hits.Load())
	}
	failing, _, _ := admin(t, http.StatusInternalServerError, nil, `{}`)
	for name, err := range map[string]error{
		"revoke consent": failing.RevokeConsentSessions(ctx, hydra.RevokeConsent{ConsentRequestID: "cr1"}),
		"revoke login":   failing.RevokeLoginSessions(ctx, hydra.RevokeLogin{Subject: "u1"}),
		"delete client":  failing.DeleteClient(ctx, "c1"),
		"list clients":   second(failing.ListClients(ctx, "")),
	} {
		if err == nil || errors.Is(err, hydra.ErrInvalidChallenge) {
			t.Errorf("%s: err = %v, want an error matching no sentinel", name, err)
		}
	}
}

const sessionsPath = "/admin/oauth2/auth/sessions/consent"

const (
	sessionItem1 = `{"consent_request_id":"cr1","grant_scope":["read","offline_access"],"remember":true,` +
		`"handled_at":"2026-11-14T10:00:00Z","consent_request":{"consent_request_id":"cr1","client":{"client_id":"c1"}}}`
	sessionItem2 = `{"consent_request_id":"cr2","grant_scope":["read"],"remember":false,"handled_at":"2026-11-14T11:00:00Z"}`
)

// pagedSessions answers the consent-session list from pages keyed by the
// page_token query ("" is the first), with the Link header next names.
func pagedSessions(t *testing.T, pages map[string]struct{ body, next string }) (*hydra.Client, *[]string) {
	t.Helper()
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		if r.Method != http.MethodGet || r.URL.Path != sessionsPath {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		p, ok := pages[r.URL.Query().Get("page_token")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if p.next != "" {
			w.Header().Set("Link", p.next)
		}
		if _, err := io.WriteString(w, p.body); err != nil {
			t.Errorf("write: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := hydra.New(hydra.Config{AdminURL: srv.URL, HTTPClient: &http.Client{Timeout: 5 * time.Second}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, &queries
}

func nextLink(token string) string {
	return `<` + sessionsPath + `?page_size=250&page_token=` + token + `>; rel="next", <` + sessionsPath + `?page_size=250&page_token=t0>; rel="first"`
}

func TestClient_ListConsentSessions_FollowsPages(t *testing.T) {
	t.Parallel()
	c, queries := pagedSessions(t, map[string]struct{ body, next string }{
		"":   {`[` + sessionItem1 + `]`, nextLink("t2")},
		"t2": {`[` + sessionItem2 + `]`, ""},
	})
	got, err := c.ListConsentSessions(t.Context(), "u 1")
	if err != nil {
		t.Fatalf("ListConsentSessions: %v", err)
	}
	want := []hydra.GrantedConsent{
		{ConsentRequestID: "cr1", ClientID: "c1", GrantScope: []string{"read", "offline_access"}, Remember: true,
			HandledAt: time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)},
		{ConsentRequestID: "cr2", GrantScope: []string{"read"}, HandledAt: time.Date(2026, 11, 14, 11, 0, 0, 0, time.UTC)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sessions =\n%+v\nwant\n%+v", got, want)
	}
	if wantQ := []string{"subject=u+1", "page_token=t2&subject=u+1"}; !reflect.DeepEqual(*queries, wantQ) {
		t.Fatalf("queries = %q, want %q", *queries, wantQ)
	}
}

// RFC 8288: rel may be a bare token or hold several space-separated types.
func TestClient_ListConsentSessions_ReadsEveryRelForm(t *testing.T) {
	t.Parallel()
	for _, link := range []string{
		`<` + sessionsPath + `?page_token=t2>; rel=next`,
		`<` + sessionsPath + `?page_token=t2>; rel="next last"`,
		`<` + sessionsPath + `?page_token=t2>; title="x"; REL="prev next"`,
	} {
		c, queries := pagedSessions(t, map[string]struct{ body, next string }{
			"":   {`[` + sessionItem1 + `]`, link},
			"t2": {`[` + sessionItem2 + `]`, ""},
		})
		got, err := c.ListConsentSessions(t.Context(), "u1")
		if err != nil || len(got) != 2 || len(*queries) != 2 {
			t.Errorf("Link %s: %d sessions, %d requests, err %v; want 2 and 2", link, len(got), len(*queries), err)
		}
	}
	c, queries := pagedSessions(t, map[string]struct{ body, next string }{
		"": {`[` + sessionItem1 + `]`, `<` + sessionsPath + `?page_token=t0>; rel="first prev"`},
	})
	if got, err := c.ListConsentSessions(t.Context(), "u1"); err != nil || len(got) != 1 || len(*queries) != 1 {
		t.Errorf("first/prev link: %d sessions, %d requests, err %v", len(got), len(*queries), err)
	}
}

// A truncated list would leave a grant unrevoked, so a next link that carries
// no page token, an unparsable one, or paging past the cap is an error.
func TestClient_ListConsentSessions_RefusesATruncatedList(t *testing.T) {
	t.Parallel()
	endless := map[string]struct{ body, next string }{}
	for i := 0; i <= 60; i++ {
		endless[strconv.Itoa(i)] = struct{ body, next string }{`[]`, nextLink(strconv.Itoa(i + 1))}
	}
	endless[""] = struct{ body, next string }{`[]`, nextLink("1")}
	tests := map[string]map[string]struct{ body, next string }{
		"next without a page token": {"": {`[]`, `<` + sessionsPath + `?page_size=250>; rel="next"`}},
		"unparsable next":           {"": {`[]`, `<%zz>; rel="next"`}},
		"endless pages":             endless,
	}
	for name, pages := range tests {
		c, queries := pagedSessions(t, pages)
		got, err := c.ListConsentSessions(t.Context(), "u1")
		if err == nil || got != nil || errors.Is(err, hydra.ErrInvalidChallenge) {
			t.Errorf("%s: got %v, err %v; want an error matching no sentinel", name, got, err)
		}
		if name == "endless pages" && len(*queries) != 50 {
			t.Errorf("%s: %d requests, want the cap of 50", name, len(*queries))
		}
	}
}

func TestClient_ListConsentSessions_Refusals(t *testing.T) {
	t.Parallel()
	c, _, hits := admin(t, http.StatusOK, nil, `[]`)
	if _, err := c.ListConsentSessions(t.Context(), ""); err == nil || hits.Load() != 0 {
		t.Fatalf("empty subject: err = %v after %d requests", err, hits.Load())
	}
	for name, status := range map[string]int{"500": 500, "404": 404} {
		failing, _, _ := admin(t, status, nil, `{}`)
		if _, err := failing.ListConsentSessions(t.Context(), "u1"); err == nil || errors.Is(err, hydra.ErrInvalidChallenge) {
			t.Errorf("%s: err = %v, want an error matching no sentinel", name, err)
		}
	}
	empty, _, _ := admin(t, http.StatusOK, nil, `[]`)
	if got, err := empty.ListConsentSessions(t.Context(), "u1"); err != nil || len(got) != 0 {
		t.Errorf("no sessions: got %v, err %v", got, err)
	}
}

// The request-object metadata decodes as sent: present values are kept; an
// absent or null value is the zero value; jwks is nil only for absent, null or {}.
func TestClient_DecodesRequestObjectMetadata(t *testing.T) {
	t.Parallel()
	const key = `{"kty":"RSA","kid":"k1","n":"x","e":"AQAB"}`
	tests := []struct {
		name, fields string
		want         hydra.OAuthClient
	}{
		{"all present", `"request_object_signing_alg":"RS256","jwks":{"keys":[` + key + `]},"jwks_uri":"https://rp.example.test/jwks",` +
			`"request_uris":["https://rp.example.test/req"]`,
			hydra.OAuthClient{RequestObjectSigningAlg: "RS256", JWKS: json.RawMessage(`{"keys":[` + key + `]}`),
				JWKSURI: "https://rp.example.test/jwks", RequestURIs: []string{"https://rp.example.test/req"}}},
		{"all absent", ``, hydra.OAuthClient{}},
		{"all null", `"request_object_signing_alg":null,"jwks":null,"jwks_uri":null,"request_uris":null`, hydra.OAuthClient{}},
		{"empty values; jwks {} is nil", `"request_object_signing_alg":"","jwks":{},"jwks_uri":"","request_uris":[]`,
			hydra.OAuthClient{RequestURIs: []string{}}},
		{"jwks with an empty key list is registered", `"jwks":{"keys":[]}`, hydra.OAuthClient{JWKS: json.RawMessage(`{"keys":[]}`)}},
		{"jwks with null keys is registered", `"jwks":{"keys":null}`, hydra.OAuthClient{JWKS: json.RawMessage(`{"keys":null}`)}},
		{"jwks with another member is registered", `"jwks":{"x":1}`, hydra.OAuthClient{JWKS: json.RawMessage(`{"x":1}`)}},
		{"jwks that is not a key set stays present", `"jwks":"x"`, hydra.OAuthClient{JWKS: json.RawMessage(`"x"`)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			body := `{"client_id":"c1"`
			if tt.fields != "" {
				body += "," + tt.fields
			}
			body += "}"
			want := tt.want
			want.ClientID = "c1"
			c, _, _ := admin(t, http.StatusOK, nil, `[`+body+`]`)
			page, err := c.ListClients(t.Context(), "")
			if err != nil || len(page.Clients) != 1 || !reflect.DeepEqual(page.Clients[0], want) {
				t.Fatalf("ListClients = %+v, %v; want %+v", page.Clients, err, want)
			}
			cr, _, _ := admin(t, http.StatusOK, nil, `{"challenge":"cc1","client":`+body+`}`)
			req, err := cr.ConsentRequest(t.Context(), "cc1")
			if err != nil || !reflect.DeepEqual(req.Client, want) {
				t.Fatalf("ConsentRequest client = %+v, %v; want %+v", req.Client, err, want)
			}
		})
	}
}
