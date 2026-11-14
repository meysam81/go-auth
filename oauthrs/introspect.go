package oauthrs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/meysam81/go-auth/v2/internal/outbound"
)

const (
	maxIntrospectionBytes = 64 << 10
	maxCacheTTL           = time.Minute
	maxCacheSize          = 1 << 20
)

// IntrospectorConfig configures token verification at an RFC 7662 endpoint.
type IntrospectorConfig struct {
	Endpoint     string           // absolute http(s) URL of the introspection endpoint
	Issuer       string           // the iss every token must carry, compared exactly
	HTTPClient   *http.Client     // required, with a Timeout; never follows a redirect
	ClientID     string           // optional HTTP Basic client authentication; both or neither
	ClientSecret string           //nolint:gosec // G117: configuration, not a literal secret
	CacheTTL     time.Duration    // 0 = no cache; at most 60 s; capped at each token's exp
	CacheSize    int              // cached tokens; 0 = 10,000; at most 1,048,576
	Now          func() time.Time // nil = time.Now
}

// Introspector verifies bearer tokens at an introspection endpoint.
type Introspector struct {
	endpoint, issuer       string
	clientID, clientSecret string
	client                 *http.Client
	now                    func() time.Time
}

// Token is what a verified access token asserts. Ext is the endpoint's ext
// member, undecoded: unmarshal it into the application's own struct.
type Token struct {
	Subject   string
	ClientID  string
	Issuer    string
	TokenUse  string // "access_token" on every Token Verify returns
	Scopes    []string
	Audience  []string
	ExpiresAt time.Time
	IssuedAt  time.Time
	Ext       json.RawMessage
}

// HasScopes reports whether t carries every one of required.
func (t Token) HasScopes(required ...string) bool {
	for _, s := range required {
		if !slices.Contains(t.Scopes, s) {
			return false
		}
	}
	return true
}

// NewIntrospector validates cfg.
func NewIntrospector(cfg IntrospectorConfig) (*Introspector, error) {
	if _, err := outbound.ParseURL(cfg.Endpoint); err != nil {
		return nil, fmt.Errorf("oauthrs: Endpoint: %w", err)
	}
	client, err := outbound.Client(cfg.HTTPClient)
	if err != nil {
		return nil, fmt.Errorf("oauthrs: %w", err)
	}
	switch {
	case cfg.Issuer == "":
		return nil, errors.New("oauthrs: Issuer is required")
	case (cfg.ClientID == "") != (cfg.ClientSecret == ""):
		return nil, errors.New("oauthrs: ClientID and ClientSecret go together")
	case cfg.CacheTTL < 0 || cfg.CacheTTL > maxCacheTTL:
		return nil, fmt.Errorf("oauthrs: CacheTTL %s outside 0 to %s", cfg.CacheTTL, maxCacheTTL)
	case cfg.CacheSize < 0 || cfg.CacheSize > maxCacheSize:
		return nil, fmt.Errorf("oauthrs: CacheSize %d outside 0 to %d", cfg.CacheSize, maxCacheSize)
	}
	in := &Introspector{
		endpoint: cfg.Endpoint, issuer: cfg.Issuer, clientID: cfg.ClientID, clientSecret: cfg.ClientSecret,
		client: client, now: cfg.Now,
	}
	if in.now == nil {
		in.now = time.Now
	}
	return in, nil
}

// Verify asks the endpoint about token and returns it only when it is an
// active access token from the issuer with a subject, a client and a future
// expiry. Every refusal matches ErrInvalidToken; any other error is an
// infrastructure failure.
func (in *Introspector) Verify(ctx context.Context, token string) (Token, error) {
	if !validToken(token) {
		return Token{}, fail("token is not a b64token of at most 4096 bytes")
	}
	return in.introspect(ctx, token)
}

type introspection struct {
	Active   bool            `json:"active"`
	TokenUse string          `json:"token_use"`
	ClientID string          `json:"client_id"`
	Subject  string          `json:"sub"`
	Issuer   string          `json:"iss"`
	Scope    string          `json:"scope"`
	Audience audience        `json:"aud"`
	Exp      int64           `json:"exp"`
	Iat      int64           `json:"iat"`
	Ext      json.RawMessage `json:"ext"`
}

// audience is the aud member: one string or an array of them.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		return nil
	}
	var one string
	if json.Unmarshal(b, &one) == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return fmt.Errorf("aud: %w", err)
	}
	*a = many
	return nil
}

func (in *Introspector) introspect(ctx context.Context, token string) (Token, error) {
	form := url.Values{"token": {token}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, in.endpoint, strings.NewReader(form))
	if err != nil {
		return Token{}, fmt.Errorf("oauthrs: introspection request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if in.clientID != "" {
		req.SetBasicAuth(url.QueryEscape(in.clientID), url.QueryEscape(in.clientSecret))
	}
	resp, err := outbound.Do(in.client, req, maxIntrospectionBytes)
	if err != nil {
		return Token{}, fmt.Errorf("oauthrs: introspection: %w", err)
	}
	if resp.Status != http.StatusOK {
		return Token{}, fmt.Errorf("oauthrs: introspection: status %d", resp.Status)
	}
	var ir introspection
	if err := json.Unmarshal(resp.Body, &ir); err != nil {
		return Token{}, fmt.Errorf("oauthrs: introspection answer: %w", err)
	}
	switch {
	case !ir.Active:
		return Token{}, fail("token is not active")
	case ir.TokenUse != "access_token":
		return Token{}, fail("token_use is not access_token")
	case ir.Issuer != in.issuer:
		return Token{}, fail("issuer differs")
	case ir.Subject == "" || ir.ClientID == "":
		return Token{}, fail("no subject or no client_id")
	case ir.Exp == 0 || !in.now().Before(time.Unix(ir.Exp, 0)):
		return Token{}, fail("no exp, or expired")
	}
	if string(ir.Ext) == "null" {
		ir.Ext = nil
	}
	return Token{
		Subject: ir.Subject, ClientID: ir.ClientID, Issuer: ir.Issuer, TokenUse: ir.TokenUse,
		Scopes: strings.Fields(ir.Scope), Audience: ir.Audience,
		ExpiresAt: time.Unix(ir.Exp, 0), IssuedAt: time.Unix(ir.Iat, 0), Ext: ir.Ext,
	}, nil
}
