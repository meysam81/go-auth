package hydra

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

const (
	loginPath   = "/admin/oauth2/auth/requests/login"
	consentPath = "/admin/oauth2/auth/requests/consent"
)

// OAuthClient is the registered OAuth 2.0 client a request comes from. Every
// field but ClientID was chosen by whoever registered the client.
type OAuthClient struct {
	ClientID                string    `json:"client_id"`
	ClientName              string    `json:"client_name"`
	RedirectURIs            []string  `json:"redirect_uris"`
	GrantTypes              []string  `json:"grant_types"`
	ResponseTypes           []string  `json:"response_types"`
	Scope                   string    `json:"scope"`
	TokenEndpointAuthMethod string    `json:"token_endpoint_auth_method"`
	CreatedAt               time.Time `json:"created_at"`
}

// LoginRequest is a login request Hydra holds for the application.
type LoginRequest struct {
	Challenge      string      `json:"challenge"`
	Skip           bool        `json:"skip"`
	Subject        string      `json:"subject"`
	RequestURL     string      `json:"request_url"`
	RequestedScope []string    `json:"requested_scope"`
	SessionID      string      `json:"session_id"`
	Client         OAuthClient `json:"client"`
}

// AcceptLogin is the application's answer that Subject signed in.
type AcceptLogin struct {
	Subject  string   `json:"subject"`
	Remember bool     `json:"remember"`
	ACR      string   `json:"acr,omitempty"`
	AMR      []string `json:"amr,omitempty"`
}

// ConsentRequest is a consent request Hydra holds for the application.
// ConsentRequestID, unlike Challenge, names the grant for
// RevokeConsent.ConsentRequestID.
type ConsentRequest struct {
	Challenge         string      `json:"challenge"`
	ConsentRequestID  string      `json:"consent_request_id"`
	Skip              bool        `json:"skip"`
	Subject           string      `json:"subject"`
	RequestURL        string      `json:"request_url"`
	RequestedScope    []string    `json:"requested_scope"`
	RequestedAudience []string    `json:"requested_access_token_audience"`
	LoginChallenge    string      `json:"login_challenge"`
	Client            OAuthClient `json:"client"`
}

// AcceptConsent is the application's grant.
type AcceptConsent struct {
	GrantScope []string       `json:"grant_scope"`
	Remember   bool           `json:"remember"`
	Session    ConsentSession `json:"session"`
}

// ConsentSession carries claims into the tokens. AccessToken becomes the
// access token's ext: a JSON object marshaled from the application's struct.
type ConsentSession struct {
	AccessToken json.RawMessage `json:"access_token,omitempty"`
}

// Reject refuses a login or consent request with an OAuth 2.0 error code;
// the client is shown both fields, so never put an internal error in them.
type Reject struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// LoginRequest reads the login request challenge names.
func (c *Client) LoginRequest(ctx context.Context, challenge string) (LoginRequest, error) {
	var out LoginRequest
	err := c.onChallenge(ctx, http.MethodGet, loginPath, "login_challenge", challenge, nil, &out)
	return out, err
}

// AcceptLogin accepts a login request and returns where to send the browser.
func (c *Client) AcceptLogin(ctx context.Context, challenge string, a AcceptLogin) (string, error) {
	if a.Subject == "" {
		return "", errors.New("hydra: AcceptLogin needs a Subject")
	}
	return c.answer(ctx, loginPath+"/accept", "login_challenge", challenge, a)
}

// RejectLogin refuses a login request and returns where to send the browser.
func (c *Client) RejectLogin(ctx context.Context, challenge string, r Reject) (string, error) {
	if r.Error == "" {
		return "", errors.New("hydra: Reject needs an Error")
	}
	return c.answer(ctx, loginPath+"/reject", "login_challenge", challenge, r)
}

// ConsentRequest reads the consent request challenge names.
func (c *Client) ConsentRequest(ctx context.Context, challenge string) (ConsentRequest, error) {
	var out ConsentRequest
	err := c.onChallenge(ctx, http.MethodGet, consentPath, "consent_challenge", challenge, nil, &out)
	return out, err
}

// AcceptConsent grants a consent request and returns where to send the
// browser.
func (c *Client) AcceptConsent(ctx context.Context, challenge string, a AcceptConsent) (string, error) {
	if at := bytes.TrimSpace(a.Session.AccessToken); len(at) > 0 && (at[0] != '{' || !json.Valid(at)) {
		return "", errors.New("hydra: Session.AccessToken must be a JSON object")
	}
	return c.answer(ctx, consentPath+"/accept", "consent_challenge", challenge, a)
}

// RejectConsent refuses a consent request and returns where to send the
// browser.
func (c *Client) RejectConsent(ctx context.Context, challenge string, r Reject) (string, error) {
	if r.Error == "" {
		return "", errors.New("hydra: Reject needs an Error")
	}
	return c.answer(ctx, consentPath+"/reject", "consent_challenge", challenge, r)
}
