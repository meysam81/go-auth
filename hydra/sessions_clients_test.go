package hydra_test

import (
	"context"
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
