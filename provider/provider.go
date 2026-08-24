// Package provider contains concrete implementations of popular OIDC and OAuth2 providers
// for seamless integration with authentication workflows.
//
// This package provides two types of provider implementations:
//
//  1. OIDC Providers (OpenID Connect): Providers that support the full OIDC specification,
//     including ID token verification and standardized claims. Examples: Google, Microsoft,
//     Auth0, Okta, Apple, GitLab.
//
//  2. OAuth2-Only Providers: Providers that only implement OAuth2 without OIDC support,
//     requiring direct calls to their user info endpoints. Examples: GitHub, Discord,
//     LinkedIn, Slack.
//
// # Usage
//
// For OIDC providers, use the provider-specific constructor which handles all OIDC
// discovery and configuration:
//
//	googleProvider, err := provider.NewGoogleProvider(ctx, clientID, clientSecret, redirectURL)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// For OAuth2-only providers, the constructor configures the OAuth2 flow and user info
// extraction logic:
//
//	githubProvider := provider.NewGitHubProvider(clientID, clientSecret, redirectURL)
//
// All providers implement the authoidc.Provider interface, making them interchangeable
// in the OIDC client:
//
//	client, err := oidc.NewClient(oidc.Config{
//	    Provider: googleProvider,
//	    // ... other config
//	})
//
// # Base Implementations
//
// The package provides two base types that handle common functionality:
//
//   - BaseOIDCProvider: For providers supporting OIDC with ID token verification
//   - OAuth2Provider: For providers that only support OAuth2 with custom user info endpoints
//
// These base types are not meant to be used directly; instead, use the provider-specific
// constructors which configure the base types appropriately.
//
// # Security
//
// Two controls in this package are not optional and are applied to every
// provider it builds.
//
// An ID token is only believed once its authorized party has been checked.
// [oidc.IDTokenVerifier] asserts that the configured client ID appears
// somewhere in aud, which is not the same as asserting the token was minted
// for us: a provider may issue a token to a different relying party and list us
// alongside it. OIDC Core section 3.1.3.7 steps 4-5 close that gap through azp,
// and this package enforces it (finding F-19, CWE-287). See
// [ErrMissingAuthorizedParty] and [ErrAuthorizedPartyMismatch].
//
// Every outbound request — discovery, JWKS, token exchange and user info —
// carries a bounded HTTP client. On an unbounded client an operator-supplied
// issuer URL is a server-side request forgery primitive against the internal
// network and a hostile response body is a memory-exhaustion primitive
// (finding F-20, CWE-918, CWE-400). The default is
// [authoidc.DefaultHTTPClient]; supply your own through
// [NewOIDCProviderWithClient] or [NewOAuth2ProviderWithClient] to impose an
// egress policy, because the address a request is allowed to reach is
// infrastructure policy and belongs to the application, not to this library.
//
// # Deprecation
//
// Every vendor-specific constructor in this package is deprecated. OIDC
// discovery configures any OIDC-capable provider from its issuer URL alone, so
// these functions are configuration rather than logic, and v2 removes them.
// Use [NewOIDCProvider] or [NewOIDCProviderWithClient] with the vendor's issuer
// URL, and [NewOAuth2Provider] or [NewOAuth2ProviderWithClient] for a provider
// that never issues an ID token.
package provider

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	authoidc "github.com/meysam81/go-auth/auth/oidc"
	"golang.org/x/oauth2"
)

var (
	// ErrNoIDToken is returned when a token response from an OIDC provider
	// carries no id_token. Without one there is nothing signed to verify, and
	// the access token alone says nothing about who authenticated.
	ErrNoIDToken = errors.New("token response contains no id_token")

	// ErrMissingAuthorizedParty is returned when an ID token names more than
	// one audience and carries no usable azp claim. OIDC Core section 3.1.3.7
	// step 5 requires azp in that case; without it the token may have been
	// minted for a different relying party that merely lists this client in a
	// multi-valued aud (finding F-19, CWE-287).
	ErrMissingAuthorizedParty = errors.New("id token has multiple audiences but no azp claim")

	// ErrAuthorizedPartyMismatch is returned when an ID token's azp claim is
	// present but names a client other than this one. The token was issued to
	// somebody else (finding F-19, CWE-287).
	ErrAuthorizedPartyMismatch = errors.New("id token azp claim does not name this client")

	// ErrNoUserInfo is returned when a provider's user info response cannot be
	// turned into a user. It covers a provider that reported an
	// application-level failure inside an HTTP 200 body, and an extract
	// function that declined the response. It exists so a caller never
	// receives a nil *authoidc.UserInfo alongside a nil error.
	ErrNoUserInfo = errors.New("provider returned no usable user info")

	// ErrUserInfoTooLarge is returned when a user info response exceeds
	// [MaxUserInfoBytes] (finding F-20, CWE-400).
	ErrUserInfoTooLarge = errors.New("user info response exceeded the maximum allowed size")

	// ErrProviderMisconfigured is returned by a constructor whose arguments
	// cannot produce a working provider. Failing here rather than at the first
	// sign-in keeps a misconfiguration out of production.
	ErrProviderMisconfigured = errors.New("provider is misconfigured")
)

const (
	// MaxUserInfoBytes bounds the user info response
	// [OAuth2Provider.ExtractUserInfo] will read. A user info document is a
	// few hundred bytes; a hostile one is not, and it is decoded into a map
	// this process holds in memory (finding F-20, CWE-400). It is deliberately
	// the same bound the OIDC client applies to a provider response, so the
	// two paths cannot drift apart.
	MaxUserInfoBytes = authoidc.DefaultMaxResponseBytes

	// userInfoErrorSnippetBytes bounds how much of a failing provider response
	// is quoted back in an error. The whole body may be megabytes and tends to
	// reach a log; a short prefix is enough to identify the failure.
	userInfoErrorSnippetBytes = 256
)

// defaultHTTPClient is built once and shared. A fresh client per call would
// mean a fresh transport per call, and a fresh transport per call leaks the
// idle connections it opened.
var defaultHTTPClient = sync.OnceValue(authoidc.DefaultHTTPClient)

// BaseOIDCProvider provides a base implementation for standard OIDC providers.
//
// This type implements the authoidc.Provider interface and handles all aspects of
// OIDC authentication including:
//   - OAuth2 authorization code flow
//   - OIDC discovery (automatic endpoint configuration)
//   - ID token verification using the provider's signing keys
//   - Standard claim extraction from ID tokens
//
// BaseOIDCProvider automatically discovers and configures provider endpoints using
// the OIDC discovery mechanism (.well-known/openid-configuration). This ensures
// compatibility with any standard OIDC provider.
//
// User information is extracted from the verified ID token, supporting standard
// OIDC claims including email, email_verified, name, picture, and preferred_username.
//
// This type should not be instantiated directly. Use NewOIDCProvider or the
// provider-specific constructors (e.g., NewGoogleProvider) instead.
type BaseOIDCProvider struct {
	name         string
	oauth2Config *oauth2.Config
	oidcProvider *oidc.Provider
	oidcVerifier *oidc.IDTokenVerifier

	// clientID is held separately from oauth2Config because
	// GetOAuth2Config hands the config out by pointer: a caller that mutates
	// ClientID there must not be able to disarm the azp check (finding F-19).
	clientID string

	// httpClient is the bounded client discovery ran on and the one the
	// provider's key set reuses for JWKS retrieval (finding F-20).
	httpClient *http.Client
}

// oidcProviderOptions carries the settings that are not part of the frozen v1
// constructor signatures.
type oidcProviderOptions struct {
	// httpClient bounds every request the provider makes. Nil selects
	// defaultHTTPClient.
	httpClient *http.Client

	// discoveryURL overrides the URL discovery is fetched from when it differs
	// from the issuer the provider reports. Empty means issuerURL.
	discoveryURL string

	// skipIssuerCheck accepts an ID token whose iss claim differs from the
	// discovered issuer. It is only correct for a provider whose issuer is
	// genuinely per-tenant and unknowable at configuration time; see
	// NewMicrosoftProvider for the one case in this package.
	skipIssuerCheck bool
}

// NewOIDCProvider creates a new OIDC provider with standard configuration.
//
// This constructor performs OIDC discovery against the issuer URL to automatically
// configure endpoints for authorization, token exchange, and key retrieval. The
// issuer URL should be the base URL of the OIDC provider (e.g., "https://accounts.google.com").
//
// Discovery, and every later JWKS retrieval by the returned provider, runs on
// [authoidc.DefaultHTTPClient]: a bounded timeout and a bounded response body.
// It does not restrict the addresses the issuer URL may resolve to. A
// deployment where the issuer URL is operator-supplied must use
// [NewOIDCProviderWithClient] and pass a client whose dialer refuses
// loopback, link-local and private ranges, or the issuer URL is a server-side
// request forgery primitive against the internal network (finding F-20,
// CWE-918).
//
// Parameters:
//   - ctx: Context for OIDC discovery HTTP requests
//   - name: Human-readable provider name (e.g., "google", "auth0")
//   - issuerURL: Base URL of the OIDC provider for discovery
//   - clientID: OAuth2 client ID obtained from the provider
//   - clientSecret: OAuth2 client secret obtained from the provider
//   - redirectURL: OAuth2 callback URL registered with the provider
//   - scopes: OAuth2 scopes to request (should include "openid" for OIDC)
//
// Returns an error if OIDC discovery fails, typically due to network issues or
// an invalid issuer URL, and [ErrProviderMisconfigured] if a required argument
// is empty.
//
// Example:
//
//	provider, err := NewOIDCProvider(
//	    ctx,
//	    "custom-oidc",
//	    "https://identity.example.com",
//	    "client-id-123",
//	    "client-secret-456",
//	    "https://myapp.com/auth/callback",
//	    []string{"openid", "email", "profile"},
//	)
func NewOIDCProvider(ctx context.Context, name, issuerURL, clientID, clientSecret, redirectURL string, scopes []string) (*BaseOIDCProvider, error) {
	return newOIDCProvider(ctx, name, issuerURL, clientID, clientSecret, redirectURL, scopes, oidcProviderOptions{})
}

// NewOIDCProviderWithClient is [NewOIDCProvider] with the HTTP client made
// explicit.
//
// The client bounds OIDC discovery performed here and every JWKS retrieval the
// returned provider performs later, because go-oidc captures the client at
// discovery time and reuses it for the key set rather than reading one from the
// verification context. A nil client selects [authoidc.DefaultHTTPClient].
//
// Supply a client with a dialer that refuses loopback, link-local and private
// address ranges whenever the issuer URL is operator-supplied. This library
// deliberately does not ship such a dialer: which addresses are reachable is
// infrastructure policy and only the application knows it (finding F-20,
// CWE-918).
//
// This exists as a separate function rather than a variadic option on
// [NewOIDCProvider] because adding a parameter — variadic or not — changes an
// exported function's type, which breaks any downstream code that assigns it
// to a variable or passes it as a value. A sibling constructor is the only
// strictly additive form within v1.
func NewOIDCProviderWithClient(ctx context.Context, httpClient *http.Client, name, issuerURL, clientID, clientSecret, redirectURL string, scopes []string) (*BaseOIDCProvider, error) {
	return newOIDCProvider(ctx, name, issuerURL, clientID, clientSecret, redirectURL, scopes, oidcProviderOptions{httpClient: httpClient})
}

func newOIDCProvider(ctx context.Context, name, issuerURL, clientID, clientSecret, redirectURL string, scopes []string, opts oidcProviderOptions) (*BaseOIDCProvider, error) {
	if name == "" {
		return nil, fmt.Errorf("provider name is required: %w", ErrProviderMisconfigured)
	}
	if issuerURL == "" {
		return nil, fmt.Errorf("provider %q: issuer URL is required: %w", name, ErrProviderMisconfigured)
	}
	// An empty client ID would make the aud and azp checks vacuous rather than
	// merely absent, so it is refused at construction (finding F-19).
	if clientID == "" {
		return nil, fmt.Errorf("provider %q: client ID is required: %w", name, ErrProviderMisconfigured)
	}

	httpClient := opts.httpClient
	if httpClient == nil {
		httpClient = defaultHTTPClient()
	}

	// F-20: go-oidc reads the client out of the context here and stores it on
	// the Provider, which is what its key set later reuses. This call is
	// therefore the only place the bound can be applied to JWKS traffic.
	discoveryCtx := oidc.ClientContext(ctx, httpClient)

	discoveryURL := opts.discoveryURL
	if discoveryURL == "" {
		discoveryURL = issuerURL
	} else {
		// The provider reports an issuer that differs from where its metadata
		// lives. go-oidc requires the expected issuer to be stated explicitly
		// so the divergence is a decision rather than an accident.
		discoveryCtx = oidc.InsecureIssuerURLContext(discoveryCtx, issuerURL)
	}

	provider, err := oidc.NewProvider(discoveryCtx, discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}

	// Verifier rather than VerifierContext: VerifierContext binds the key set
	// to the context passed here, and a constructor is routinely called with a
	// request-scoped context that is canceled long before the first sign-in.
	verifier := provider.Verifier(&oidc.Config{
		ClientID:        clientID,
		SkipIssuerCheck: opts.skipIssuerCheck,
	})

	return &BaseOIDCProvider{
		name:         name,
		oauth2Config: oauth2Config,
		oidcProvider: provider,
		oidcVerifier: verifier,
		clientID:     clientID,
		httpClient:   httpClient,
	}, nil
}

// Name returns the human-readable name of the provider.
//
// This implements the authoidc.Provider interface.
func (p *BaseOIDCProvider) Name() string {
	return p.name
}

// GetOAuth2Config returns the OAuth2 configuration used for authorization flows.
//
// This implements the authoidc.Provider interface and provides access to the
// underlying OAuth2 configuration, which includes client credentials, scopes,
// and endpoint URLs.
//
// The returned pointer aliases the provider's own configuration. Mutating it
// changes how the provider behaves; it does not weaken ID token verification,
// which is pinned to the client ID supplied at construction.
func (p *BaseOIDCProvider) GetOAuth2Config() *oauth2.Config {
	return p.oauth2Config
}

// GetOIDCProvider returns the underlying OIDC provider instance.
//
// This implements the authoidc.Provider interface and provides access to the
// raw OIDC provider, which can be used for advanced operations like retrieving
// provider metadata or performing custom token verification.
func (p *BaseOIDCProvider) GetOIDCProvider() *oidc.Provider {
	return p.oidcProvider
}

// HTTPClient returns the bounded HTTP client this provider performs discovery
// and JWKS retrieval with. It is never nil.
//
// It is exposed so an application can reuse the same egress policy for its own
// calls to the provider, and so a test can assert which client is in force.
func (p *BaseOIDCProvider) HTTPClient() *http.Client {
	return p.httpClient
}

// ExtractUserInfo extracts and verifies user information from an OAuth2 token.
//
// This method implements the authoidc.Provider interface and performs the following:
//  1. Extracts the ID token from the OAuth2 token response
//  2. Verifies the ID token signature using the provider's public keys
//  3. Validates the token claims (issuer, audience, expiration)
//  4. Verifies the authorized party (azp) against the configured client ID
//  5. Extracts standard OIDC claims into a UserInfo struct
//
// Step 4 is what distinguishes "this client is listed in aud" from "this token
// was minted for this client". OIDC Core section 3.1.3.7 step 5 requires azp
// whenever aud holds more than one value, and requires it to equal the client
// ID whenever it is present at all. Skipping it accepts a token issued to a
// different relying party that happens to name this one alongside itself
// (finding F-19, CWE-287).
//
// The following standard OIDC claims are extracted when present:
//   - sub (subject): Unique user identifier
//   - email: User's email address
//   - email_verified: Whether the email has been verified
//   - name: User's full name
//   - picture: URL to user's profile picture
//   - preferred_username: User's preferred username
//
// All raw claims from the ID token are preserved in UserInfo.RawClaims for
// provider-specific claim extraction. The OIDC client reads the nonce back out
// of that map, so it must not be filtered here.
//
// Returns an error if:
//   - The token response does not contain an ID token ([ErrNoIDToken])
//   - The ID token signature verification fails
//   - The ID token claims are invalid or expired
//   - The authorized party is missing or wrong ([ErrMissingAuthorizedParty],
//     [ErrAuthorizedPartyMismatch])
func (p *BaseOIDCProvider) ExtractUserInfo(ctx context.Context, token *oauth2.Token) (*authoidc.UserInfo, error) {
	if token == nil {
		return nil, fmt.Errorf("provider %q: %w", p.name, ErrNoIDToken)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("provider %q: %w", p.name, ErrNoIDToken)
	}

	// The verifier's key set already carries the bounded client captured at
	// construction, so no client needs to be threaded onto ctx here.
	idToken, err := p.oidcVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	if err := verifyAuthorizedParty(p.clientID, idToken.Audience, claims); err != nil {
		return nil, fmt.Errorf("provider %q: %w", p.name, err)
	}

	userInfo := &authoidc.UserInfo{
		Subject:   idToken.Subject,
		RawClaims: claims,
	}

	if email, ok := claims["email"].(string); ok {
		userInfo.Email = email
	}
	if emailVerified, ok := claims["email_verified"].(bool); ok {
		userInfo.EmailVerified = emailVerified
	}
	if name, ok := claims["name"].(string); ok {
		userInfo.Name = name
	}
	if picture, ok := claims["picture"].(string); ok {
		userInfo.Picture = picture
	}
	if username, ok := claims["preferred_username"].(string); ok {
		userInfo.Username = username
	}

	return userInfo, nil
}

// verifyAuthorizedParty implements OIDC Core section 3.1.3.7 steps 4 and 5
// (finding F-19, CWE-287).
//
// Two rules, and the second is the one that is usually missed: azp is required
// when aud names more than one party, and azp must equal the client ID whenever
// it is present, however many audiences there are. A provider that emits azp on
// a single-audience token is telling us who the token is for, and disagreeing
// with it is a mix-up.
//
// The comparison is constant-time. Both operands are public identifiers rather
// than secrets, so this is cheap insurance against a client ID that is treated
// as confidential in some deployment, not a defense the design rests on.
func verifyAuthorizedParty(clientID string, audience []string, claims map[string]interface{}) error {
	raw, present := claims["azp"]
	if !present {
		if len(audience) > 1 {
			return ErrMissingAuthorizedParty
		}
		return nil
	}

	azp, ok := raw.(string)
	if !ok || azp == "" {
		// azp is present but is not a usable party name. Treating that as
		// "absent" would let a hostile provider suppress the check on a
		// multi-audience token by emitting azp: null.
		return ErrMissingAuthorizedParty
	}

	if subtle.ConstantTimeCompare([]byte(azp), []byte(clientID)) != 1 {
		return ErrAuthorizedPartyMismatch
	}
	return nil
}

// OAuth2Provider provides a base implementation for OAuth2-only providers (non-OIDC).
//
// This type implements the authoidc.Provider interface for providers that support
// OAuth2 but do not implement the full OIDC specification. Unlike OIDC providers,
// OAuth2-only providers do not issue ID tokens, so user information must be
// retrieved from a provider-specific user info endpoint.
//
// OAuth2Provider handles:
//   - OAuth2 authorization code flow
//   - Token exchange with the provider
//   - HTTP requests to the provider's user info endpoint
//   - Custom user info extraction via provider-specific logic
//
// The extractFunc parameter allows each provider to define custom logic for
// parsing their specific user info response format into a standardized UserInfo
// struct. This flexibility enables support for providers with non-standard
// response schemas.
//
// Common OAuth2-only providers include GitHub, Discord, LinkedIn, and Slack,
// which have their own user info endpoint formats.
//
// An OAuth2-only provider issues no ID token, so none of the ID token controls
// apply to it: there is no signature, no audience, no azp and no nonce. Its
// only evidence is a bearer token presented to an endpoint over TLS. Prefer an
// OIDC provider wherever the vendor offers one.
//
// This type should not be instantiated directly. Use NewOAuth2Provider or the
// provider-specific constructors (e.g., NewGitHubProvider) instead.
type OAuth2Provider struct {
	name         string
	oauth2Config *oauth2.Config
	userInfoURL  string
	extractFunc  func(map[string]interface{}) *authoidc.UserInfo

	// httpClient, when non-nil, is the client the user info request is made
	// with, overriding anything on the context (finding F-20).
	httpClient *http.Client
}

// NewOAuth2Provider creates a new OAuth2-only provider.
//
// This constructor creates a provider for OAuth2 services that do not support OIDC.
// Unlike OIDC providers, the endpoints must be manually configured in the oauth2Config.
//
// Parameters:
//   - name: Human-readable provider name (e.g., "github", "discord")
//   - oauth2Config: Fully configured OAuth2 config with endpoints, client credentials,
//     redirect URL, and scopes
//   - userInfoURL: The provider's user info endpoint URL (e.g., "https://api.github.com/user")
//   - extractFunc: Custom function to parse the provider's user info response into
//     a standardized UserInfo struct
//
// The extractFunc should handle provider-specific response formats and map fields
// to the standard UserInfo structure. It receives the raw JSON response as a map
// and should return a populated UserInfo struct. Returning nil rejects the
// response: [OAuth2Provider.ExtractUserInfo] turns that into [ErrNoUserInfo]
// rather than handing the caller a nil user with a nil error. Use it for a
// provider that reports application-level failures inside an HTTP 200 body.
//
// The user info request is made with [authoidc.DefaultHTTPClient] unless the
// context carries one, which the OIDC client does during a callback. Use
// [NewOAuth2ProviderWithClient] to pin a client of your own (finding F-20).
//
// Example:
//
//	extractFunc := func(data map[string]interface{}) *authoidc.UserInfo {
//	    login, _ := data["login"].(string)
//	    if login == "" {
//	        return nil
//	    }
//	    return &authoidc.UserInfo{
//	        Subject:   fmt.Sprintf("%v", data["id"]),
//	        Username:  login,
//	        RawClaims: data,
//	    }
//	}
//	provider := NewOAuth2Provider("github", oauth2Config, userInfoURL, extractFunc)
func NewOAuth2Provider(name string, oauth2Config *oauth2.Config, userInfoURL string, extractFunc func(map[string]interface{}) *authoidc.UserInfo) *OAuth2Provider {
	return &OAuth2Provider{
		name:         name,
		oauth2Config: oauth2Config,
		userInfoURL:  userInfoURL,
		extractFunc:  extractFunc,
	}
}

// NewOAuth2ProviderWithClient is [NewOAuth2Provider] with the HTTP client made
// explicit.
//
// The client is used for the user info request and takes precedence over any
// client on the context. A nil client restores the default behavior: the
// context's client if it carries one, otherwise
// [authoidc.DefaultHTTPClient].
//
// Supply a client whose dialer refuses loopback, link-local and private address
// ranges whenever the user info URL is operator-supplied (finding F-20,
// CWE-918). It exists as a separate function for the same reason as
// [NewOIDCProviderWithClient]: v1 cannot change an exported signature.
func NewOAuth2ProviderWithClient(name string, oauth2Config *oauth2.Config, userInfoURL string, extractFunc func(map[string]interface{}) *authoidc.UserInfo, httpClient *http.Client) *OAuth2Provider {
	p := NewOAuth2Provider(name, oauth2Config, userInfoURL, extractFunc)
	p.httpClient = httpClient
	return p
}

// Name returns the human-readable name of the provider.
//
// This implements the authoidc.Provider interface.
func (p *OAuth2Provider) Name() string {
	return p.name
}

// GetOAuth2Config returns the OAuth2 configuration used for authorization flows.
//
// This implements the authoidc.Provider interface and provides access to the
// underlying OAuth2 configuration, which includes client credentials, scopes,
// and endpoint URLs.
func (p *OAuth2Provider) GetOAuth2Config() *oauth2.Config {
	return p.oauth2Config
}

// GetOIDCProvider returns nil for OAuth2-only providers.
//
// This implements the authoidc.Provider interface. Since OAuth2-only providers
// do not support OIDC, this method always returns nil. Use ExtractUserInfo
// instead to retrieve user information from the provider's user info endpoint.
func (p *OAuth2Provider) GetOIDCProvider() *oidc.Provider {
	return nil
}

// ExtractUserInfo retrieves user information from the provider's user info endpoint.
//
// This method implements the authoidc.Provider interface for OAuth2-only providers.
// Unlike OIDC providers that extract user info from ID tokens, this method performs
// the following steps:
//  1. Creates an authenticated HTTP client using the OAuth2 token
//  2. Sends a GET request to the provider's user info endpoint
//  3. Reads at most [MaxUserInfoBytes] of the response and parses it as JSON
//  4. Calls the provider-specific extractFunc to convert the response to UserInfo
//
// The extractFunc was configured during provider construction and handles the
// provider-specific response format. If it declines the response by returning
// nil, this method reports [ErrNoUserInfo]; it never returns a nil UserInfo
// with a nil error.
//
// The response body is bounded because it is decoded into a map held in memory
// and the provider is not necessarily trustworthy (finding F-20, CWE-400).
//
// Returns an error if:
//   - The HTTP request to the user info endpoint fails
//   - The response exceeds [MaxUserInfoBytes] ([ErrUserInfoTooLarge])
//   - The provider returns a non-200 status code
//   - The response body cannot be parsed as JSON
//   - The extract function declines the response ([ErrNoUserInfo])
func (p *OAuth2Provider) ExtractUserInfo(ctx context.Context, token *oauth2.Token) (info *authoidc.UserInfo, err error) {
	if p.oauth2Config == nil {
		return nil, fmt.Errorf("provider %q has no OAuth2 config: %w", p.name, ErrProviderMisconfigured)
	}
	if p.extractFunc == nil {
		return nil, fmt.Errorf("provider %q has no user info extractor: %w", p.name, ErrProviderMisconfigured)
	}

	ctx = p.clientContext(ctx)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.userInfoURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to build user info request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := p.oauth2Config.Client(ctx, token).Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info: %w", err)
	}
	defer func() {
		// A failed close is a connection this process no longer gets back, so
		// it is reported rather than discarded. errors.Join rather than an
		// overwrite: when the body already failed, both facts matter and
		// errors.Is still finds either one. A close failure must never leave a
		// user attached to an error.
		if cerr := resp.Body.Close(); cerr != nil {
			info = nil
			err = errors.Join(err, fmt.Errorf("failed to close user info response body: %w", cerr))
		}
	}()

	// One byte of headroom so a body of exactly MaxUserInfoBytes still reads to
	// completion rather than tripping the limit.
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxUserInfoBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read user info response: %w", err)
	}
	if int64(len(body)) > MaxUserInfoBytes {
		return nil, fmt.Errorf("provider %q: %w", p.name, ErrUserInfoTooLarge)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user info request failed with status %d: %s", resp.StatusCode, errorSnippet(body))
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	// A provider-supplied extractor may decline the response — an
	// application-level error inside a 200, or a shape it does not recognize.
	// Returning its nil unchanged handed the caller a nil user and a nil error,
	// which is a nil dereference one frame up.
	userInfo := p.extractFunc(data)
	if userInfo == nil {
		return nil, fmt.Errorf("provider %q: %w", p.name, ErrNoUserInfo)
	}

	return userInfo, nil
}

// clientContext decides which HTTP client the user info request runs on
// (finding F-20).
//
// Precedence is explicit-over-inherited-over-default: a client pinned on the
// provider is the operator's decision about this provider specifically; a
// client already on the context belongs to the OIDC client driving the
// callback and must not be overridden by a default; only when neither exists
// does the bounded package default apply, so that a provider used outside a
// callback is never left on http.DefaultClient.
func (p *OAuth2Provider) clientContext(ctx context.Context) context.Context {
	if p.httpClient != nil {
		return oidc.ClientContext(ctx, p.httpClient)
	}
	if _, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		return ctx
	}
	return oidc.ClientContext(ctx, defaultHTTPClient())
}

// errorSnippet bounds how much of a provider's response reaches an error
// string, which routinely reaches a log.
func errorSnippet(body []byte) string {
	if len(body) <= userInfoErrorSnippetBytes {
		return string(body)
	}
	return string(body[:userInfoErrorSnippetBytes]) + "... (truncated)"
}
