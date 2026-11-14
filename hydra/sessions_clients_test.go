package hydra_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

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
