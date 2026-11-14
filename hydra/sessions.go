package hydra

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
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
	if page.NextPageToken, err = nextLinkToken(h); err != nil {
		return ClientPage{}, err
	}
	return page, nil
}

// nextLinkToken reads page_token from the Link header's rel="next" target.
// A list with no such link has no next page (""); a link it cannot follow, a
// target that does not parse or carries no page_token, is an error, so a list
// is never silently cut short.
func nextLinkToken(h http.Header) (string, error) {
	for _, link := range h.Values("Link") {
		for part := range strings.SplitSeq(link, ",") {
			target, params, ok := strings.Cut(strings.TrimSpace(part), ";")
			if !ok || !hasRel(params, "next") {
				continue
			}
			u, err := url.Parse(strings.Trim(target, "<>"))
			if err != nil {
				return "", errors.New("hydra: the next-page link does not parse")
			}
			token := u.Query().Get("page_token")
			if token == "" {
				return "", errors.New("hydra: the next-page link has no page_token")
			}
			return token, nil
		}
	}
	return "", nil
}

// hasRel reports whether a link's parameters carry a rel naming want, quoted
// or a bare token, among space-separated relation types (RFC 8288 section
// 3.3).
func hasRel(params, want string) bool {
	for param := range strings.SplitSeq(params, ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(param), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "rel") {
			continue
		}
		if slices.ContainsFunc(strings.Fields(strings.Trim(strings.TrimSpace(value), `"`)), func(r string) bool {
			return strings.EqualFold(r, want)
		}) {
			return true
		}
	}
	return false
}

// maxConsentSessionPages bounds ListConsentSessions: a server that never
// stops paging is an error, not an endless loop.
const maxConsentSessionPages = 50

// GrantedConsent is one consent a subject granted. ClientID is empty when
// Hydra does not say which client.
type GrantedConsent struct {
	ConsentRequestID string
	ClientID         string
	GrantScope       []string
	Remember         bool
	HandledAt        time.Time
}

type grantedConsentWire struct {
	ConsentRequestID string                `json:"consent_request_id"`
	GrantScope       []string              `json:"grant_scope"`
	Remember         bool                  `json:"remember"`
	HandledAt        time.Time             `json:"handled_at"`
	ConsentRequest   *grantedConsentSource `json:"consent_request"`
}

type grantedConsentSource struct {
	Client *grantedConsentClient `json:"client"`
}

type grantedConsentClient struct {
	ClientID string `json:"client_id"`
}

// ListConsentSessions returns every consent subject granted, following the
// admin API's next-page links. A list it cannot read to the end (a link
// without a page token, or more than 50 pages) is an error, never a
// truncated answer: a sweep that revokes from it must not miss a grant.
func (c *Client) ListConsentSessions(ctx context.Context, subject string) ([]GrantedConsent, error) {
	if subject == "" {
		return nil, errors.New("hydra: ListConsentSessions needs a subject")
	}
	var all []GrantedConsent
	pageToken := ""
	for range maxConsentSessionPages {
		q := url.Values{"subject": {subject}}
		if pageToken != "" {
			q.Set("page_token", pageToken)
		}
		var page []grantedConsentWire
		h, err := c.do(ctx, http.MethodGet, "/admin/oauth2/auth/sessions/consent", q, nil, &page)
		if err != nil {
			return nil, err
		}
		for _, w := range page {
			g := GrantedConsent{ConsentRequestID: w.ConsentRequestID, GrantScope: w.GrantScope, Remember: w.Remember, HandledAt: w.HandledAt}
			if w.ConsentRequest != nil && w.ConsentRequest.Client != nil {
				g.ClientID = w.ConsentRequest.Client.ClientID
			}
			all = append(all, g)
		}
		if pageToken, err = nextLinkToken(h); err != nil {
			return nil, err
		}
		if pageToken == "" {
			return all, nil
		}
	}
	return nil, fmt.Errorf("hydra: consent sessions run past %d pages", maxConsentSessionPages)
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
