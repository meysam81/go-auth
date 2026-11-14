package hydra

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// RevokeConsent selects consent sessions to revoke: ConsentRequestID alone
// (one grant), or Subject with exactly one of Client and All. Revoking a
// consent session invalidates its access and refresh tokens.
type RevokeConsent struct {
	ConsentRequestID string
	Subject          string
	Client           string
	All              bool
}

// RevokeConsentSessions revokes the consent sessions r selects.
func (c *Client) RevokeConsentSessions(ctx context.Context, r RevokeConsent) error {
	q := url.Values{}
	switch {
	case r.ConsentRequestID != "" && r.Subject == "" && r.Client == "" && !r.All:
		q.Set("consent_request_id", r.ConsentRequestID)
	case r.ConsentRequestID == "" && r.Subject != "" && (r.Client != "") != r.All:
		q.Set("subject", r.Subject)
		if r.All {
			q.Set("all", "true")
		} else {
			q.Set("client", r.Client)
		}
	default:
		return errors.New("hydra: RevokeConsent needs ConsentRequestID alone, or Subject with exactly one of Client and All")
	}
	_, err := c.do(ctx, http.MethodDelete, "/admin/oauth2/auth/sessions/consent", q, nil, nil)
	return err
}

// RevokeLogin selects login sessions to end: every one of Subject, or the
// one SessionID names; exactly one of them.
type RevokeLogin struct {
	Subject   string
	SessionID string
}

// RevokeLoginSessions ends the login sessions r selects.
func (c *Client) RevokeLoginSessions(ctx context.Context, r RevokeLogin) error {
	q := url.Values{}
	switch {
	case r.Subject != "" && r.SessionID == "":
		q.Set("subject", r.Subject)
	case r.Subject == "" && r.SessionID != "":
		q.Set("sid", r.SessionID)
	default:
		return errors.New("hydra: RevokeLogin needs exactly one of Subject and SessionID")
	}
	_, err := c.do(ctx, http.MethodDelete, "/admin/oauth2/auth/sessions/login", q, nil, nil)
	return err
}

// ClientPage is one page of registered clients; NextPageToken is empty on
// the last page.
type ClientPage struct {
	Clients       []OAuthClient
	NextPageToken string
}

// ListClients returns the page pageToken names; pass "" for the first.
func (c *Client) ListClients(ctx context.Context, pageToken string) (ClientPage, error) {
	var q url.Values
	if pageToken != "" {
		q = url.Values{"page_token": {pageToken}}
	}
	var page ClientPage
	h, err := c.do(ctx, http.MethodGet, "/admin/clients", q, nil, &page.Clients)
	if err != nil {
		return ClientPage{}, err
	}
	page.NextPageToken = nextPageToken(h)
	return page, nil
}

// nextPageToken reads page_token from the Link header's rel="next" target.
func nextPageToken(h http.Header) string {
	for _, link := range h.Values("Link") {
		for part := range strings.SplitSeq(link, ",") {
			target, params, ok := strings.Cut(strings.TrimSpace(part), ";")
			if !ok || !strings.Contains(params, `rel="next"`) {
				continue
			}
			if u, err := url.Parse(strings.Trim(target, "<>")); err == nil {
				return u.Query().Get("page_token")
			}
		}
	}
	return ""
}

// DeleteClient deletes a registered client. A client that is already gone
// is not an error.
func (c *Client) DeleteClient(ctx context.Context, id string) error {
	if id == "" || id == "." || id == ".." {
		return errors.New("hydra: DeleteClient needs a client id")
	}
	_, err := c.do(ctx, http.MethodDelete, "/admin/clients/"+url.PathEscape(id), nil, nil, nil)
	var se *statusError
	if errors.As(err, &se) && se.status == http.StatusNotFound {
		return nil
	}
	return err
}
