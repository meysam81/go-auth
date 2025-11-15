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
package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	authoidc "github.com/meysam81/go-auth/auth/oidc"
	"golang.org/x/oauth2"
)

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
}

// NewOIDCProvider creates a new OIDC provider with standard configuration.
//
// This constructor performs OIDC discovery against the issuer URL to automatically
// configure endpoints for authorization, token exchange, and key retrieval. The
// issuer URL should be the base URL of the OIDC provider (e.g., "https://accounts.google.com").
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
// an invalid issuer URL.
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
	provider, err := oidc.NewProvider(ctx, issuerURL)
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

	verifier := provider.Verifier(&oidc.Config{
		ClientID: clientID,
	})

	return &BaseOIDCProvider{
		name:         name,
		oauth2Config: oauth2Config,
		oidcProvider: provider,
		oidcVerifier: verifier,
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

// ExtractUserInfo extracts and verifies user information from an OAuth2 token.
//
// This method implements the authoidc.Provider interface and performs the following:
//  1. Extracts the ID token from the OAuth2 token response
//  2. Verifies the ID token signature using the provider's public keys
//  3. Validates the token claims (issuer, audience, expiration)
//  4. Extracts standard OIDC claims into a UserInfo struct
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
// provider-specific claim extraction.
//
// Returns an error if:
//   - The token response does not contain an ID token
//   - The ID token signature verification fails
//   - The ID token claims are invalid or expired
func (p *BaseOIDCProvider) ExtractUserInfo(ctx context.Context, token *oauth2.Token) (*authoidc.UserInfo, error) {
	// Extract ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("no id_token in token response")
	}

	// Verify ID token
	idToken, err := p.oidcVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	// Extract claims
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	userInfo := &authoidc.UserInfo{
		Subject:   idToken.Subject,
		RawClaims: claims,
	}

	// Extract standard claims
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
// This type should not be instantiated directly. Use NewOAuth2Provider or the
// provider-specific constructors (e.g., NewGitHubProvider) instead.
type OAuth2Provider struct {
	name         string
	oauth2Config *oauth2.Config
	userInfoURL  string
	extractFunc  func(map[string]interface{}) *authoidc.UserInfo
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
// and should return a populated UserInfo struct.
//
// Example:
//
//	extractFunc := func(data map[string]interface{}) *authoidc.UserInfo {
//	    return &authoidc.UserInfo{
//	        Subject:  fmt.Sprintf("%v", data["id"]),
//	        Email:    data["email"].(string),
//	        Username: data["login"].(string),
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
//  3. Parses the JSON response
//  4. Calls the provider-specific extractFunc to convert the response to UserInfo
//
// The extractFunc was configured during provider construction and handles the
// provider-specific response format.
//
// Returns an error if:
//   - The HTTP request to the user info endpoint fails
//   - The provider returns a non-200 status code
//   - The response body cannot be parsed as JSON
func (p *OAuth2Provider) ExtractUserInfo(ctx context.Context, token *oauth2.Token) (*authoidc.UserInfo, error) {
	// Call user info endpoint
	client := p.oauth2Config.Client(ctx, token)
	resp, err := client.Get(p.userInfoURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("user info request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	return p.extractFunc(data), nil
}
