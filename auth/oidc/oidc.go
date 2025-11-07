// Package oidc provides OpenID Connect client authentication for SSO.
package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/meysam81/go-auth/storage"
	"golang.org/x/oauth2"
)

var (
	// ErrInvalidState is returned when the OAuth2 state parameter is invalid.
	ErrInvalidState = errors.New("invalid state parameter")

	// ErrProviderNotFound is returned when a provider isn't configured.
	ErrProviderNotFound = errors.New("provider not found")

	// ErrExchangeFailed is returned when the OAuth2 code exchange fails.
	ErrExchangeFailed = errors.New("failed to exchange authorization code")

	// ErrUserInfoFailed is returned when fetching user info fails.
	ErrUserInfoFailed = errors.New("failed to fetch user info")
)

// Provider defines the interface for an OIDC/OAuth2 provider.
type Provider interface {
	// Name returns the provider's unique name (e.g., "google", "github").
	Name() string

	// GetOAuth2Config returns the OAuth2 configuration.
	GetOAuth2Config() *oauth2.Config

	// GetOIDCProvider returns the OIDC provider (nil for OAuth2-only providers).
	GetOIDCProvider() *oidc.Provider

	// ExtractUserInfo extracts user information from the OAuth2 token.
	// For OIDC providers, this validates the ID token and extracts claims.
	// For OAuth2-only providers (e.g., GitHub), this calls the user info endpoint.
	ExtractUserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error)
}

// UserInfo represents user information extracted from an OIDC/OAuth2 provider.
type UserInfo struct {
	Subject       string                 `json:"sub"`           // Unique user ID from provider
	Email         string                 `json:"email"`
	EmailVerified bool                   `json:"email_verified"`
	Name          string                 `json:"name,omitempty"`
	Username      string                 `json:"username,omitempty"`
	Picture       string                 `json:"picture,omitempty"`
	Provider      string                 `json:"provider"` // Provider name
	RawClaims     map[string]interface{} `json:"raw_claims,omitempty"`
}

// Client handles OIDC authentication flows.
type Client struct {
	providers   map[string]Provider
	userStore   storage.UserStore
	stateStore  storage.OIDCStateStore
	redirectURL string // Default redirect URL
}

// Config configures the OIDC client.
type Config struct {
	Providers   []Provider
	UserStore   storage.UserStore
	StateStore  storage.OIDCStateStore
	RedirectURL string // Optional: default redirect URL after authentication
}

// NewClient creates a new OIDC client.
func NewClient(cfg Config) (*Client, error) {
	if len(cfg.Providers) == 0 {
		return nil, errors.New("at least one provider is required")
	}
	if cfg.UserStore == nil {
		return nil, errors.New("user store is required")
	}
	if cfg.StateStore == nil {
		return nil, errors.New("state store is required")
	}

	providers := make(map[string]Provider)
	for _, p := range cfg.Providers {
		providers[p.Name()] = p
	}

	return &Client{
		providers:   providers,
		userStore:   cfg.UserStore,
		stateStore:  cfg.StateStore,
		redirectURL: cfg.RedirectURL,
	}, nil
}

// AuthURLOptions configures the authorization URL generation.
type AuthURLOptions struct {
	Provider    string
	RedirectURL string                 // Optional: overrides default redirect URL
	Scopes      []string               // Optional: overrides provider default scopes
	Metadata    map[string]interface{} // Optional: additional state data
}

// GetAuthorizationURL generates an OAuth2/OIDC authorization URL.
func (c *Client) GetAuthorizationURL(ctx context.Context, opts AuthURLOptions) (string, error) {
	provider, exists := c.providers[opts.Provider]
	if !exists {
		return "", ErrProviderNotFound
	}

	// Generate secure state
	state, err := generateState()
	if err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}

	// Store state with metadata
	redirectURL := opts.RedirectURL
	if redirectURL == "" {
		redirectURL = c.redirectURL
	}

	stateData := &storage.OIDCState{
		RedirectURL: redirectURL,
		Provider:    opts.Provider,
		Metadata:    opts.Metadata,
	}

	if err := c.stateStore.StoreState(ctx, state, stateData, 10*time.Minute); err != nil {
		return "", fmt.Errorf("failed to store state: %w", err)
	}

	// Get OAuth2 config
	oauth2Config := provider.GetOAuth2Config()

	// Build authorization URL
	authURL := oauth2Config.AuthCodeURL(state)

	// Add scopes if provided
	if len(opts.Scopes) > 0 {
		oauth2Config = &oauth2.Config{
			ClientID:     oauth2Config.ClientID,
			ClientSecret: oauth2Config.ClientSecret,
			Endpoint:     oauth2Config.Endpoint,
			RedirectURL:  oauth2Config.RedirectURL,
			Scopes:       opts.Scopes,
		}
		authURL = oauth2Config.AuthCodeURL(state)
	}

	return authURL, nil
}

// CallbackResult represents the result of an OAuth2 callback.
type CallbackResult struct {
	User        *storage.User
	UserInfo    *UserInfo
	IsNewUser   bool
	RedirectURL string
	Metadata    map[string]interface{}
}

// HandleCallback processes the OAuth2 callback and returns user information.
func (c *Client) HandleCallback(ctx context.Context, state, code string) (*CallbackResult, error) {
	// Validate state
	stateData, err := c.stateStore.GetState(ctx, state)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) || errors.Is(err, storage.ErrExpired) {
			return nil, ErrInvalidState
		}
		return nil, fmt.Errorf("failed to get state: %w", err)
	}

	// Get provider
	provider, exists := c.providers[stateData.Provider]
	if !exists {
		return nil, ErrProviderNotFound
	}

	// Exchange code for token
	oauth2Config := provider.GetOAuth2Config()
	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, ErrExchangeFailed
	}

	// Extract user info
	userInfo, err := provider.ExtractUserInfo(ctx, token)
	if err != nil {
		return nil, err
	}

	userInfo.Provider = stateData.Provider

	// Find or create user
	user, isNewUser, err := c.findOrCreateUser(ctx, userInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to find or create user: %w", err)
	}

	return &CallbackResult{
		User:        user,
		UserInfo:    userInfo,
		IsNewUser:   isNewUser,
		RedirectURL: stateData.RedirectURL,
		Metadata:    stateData.Metadata,
	}, nil
}

// GetProvider returns a registered provider by name.
func (c *Client) GetProvider(name string) (Provider, error) {
	provider, exists := c.providers[name]
	if !exists {
		return nil, ErrProviderNotFound
	}
	return provider, nil
}

// ListProviders returns all registered provider names.
func (c *Client) ListProviders() []string {
	names := make([]string, 0, len(c.providers))
	for name := range c.providers {
		names = append(names, name)
	}
	return names
}

// findOrCreateUser finds an existing user by email or creates a new one.
func (c *Client) findOrCreateUser(ctx context.Context, userInfo *UserInfo) (*storage.User, bool, error) {
	// Try to find existing user by email
	if userInfo.Email != "" {
		user, err := c.userStore.GetUserByEmail(ctx, userInfo.Email)
		if err == nil {
			return user, false, nil
		}
		if !errors.Is(err, storage.ErrNotFound) {
			return nil, false, fmt.Errorf("failed to query user: %w", err)
		}
	}

	// Create new user
	userID, err := generateUserID()
	if err != nil {
		return nil, false, fmt.Errorf("failed to generate user ID: %w", err)
	}

	user := &storage.User{
		ID:       userID,
		Email:    userInfo.Email,
		Username: userInfo.Username,
		Name:     userInfo.Name,
		Provider: userInfo.Provider,
		Metadata: map[string]interface{}{
			"provider_sub": userInfo.Subject,
			"picture":      userInfo.Picture,
			"raw_claims":   userInfo.RawClaims,
		},
	}

	if err := c.userStore.CreateUser(ctx, user); err != nil {
		return nil, false, fmt.Errorf("failed to create user: %w", err)
	}

	return user, true, nil
}

// generateState generates a cryptographically secure state parameter.
func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// generateUserID generates a cryptographically secure user ID.
func generateUserID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
