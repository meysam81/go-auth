// Package provider contains concrete implementations of OIDC/OAuth2 providers.
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
type BaseOIDCProvider struct {
	name         string
	oauth2Config *oauth2.Config
	oidcProvider *oidc.Provider
	oidcVerifier *oidc.IDTokenVerifier
}

// NewOIDCProvider creates a new OIDC provider with standard configuration.
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

func (p *BaseOIDCProvider) Name() string {
	return p.name
}

func (p *BaseOIDCProvider) GetOAuth2Config() *oauth2.Config {
	return p.oauth2Config
}

func (p *BaseOIDCProvider) GetOIDCProvider() *oidc.Provider {
	return p.oidcProvider
}

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
type OAuth2Provider struct {
	name         string
	oauth2Config *oauth2.Config
	userInfoURL  string
	extractFunc  func(map[string]interface{}) *authoidc.UserInfo
}

// NewOAuth2Provider creates a new OAuth2-only provider.
func NewOAuth2Provider(name string, oauth2Config *oauth2.Config, userInfoURL string, extractFunc func(map[string]interface{}) *authoidc.UserInfo) *OAuth2Provider {
	return &OAuth2Provider{
		name:         name,
		oauth2Config: oauth2Config,
		userInfoURL:  userInfoURL,
		extractFunc:  extractFunc,
	}
}

func (p *OAuth2Provider) Name() string {
	return p.name
}

func (p *OAuth2Provider) GetOAuth2Config() *oauth2.Config {
	return p.oauth2Config
}

func (p *OAuth2Provider) GetOIDCProvider() *oidc.Provider {
	return nil
}

func (p *OAuth2Provider) ExtractUserInfo(ctx context.Context, token *oauth2.Token) (*authoidc.UserInfo, error) {
	// Call user info endpoint
	client := p.oauth2Config.Client(ctx, token)
	resp, err := client.Get(p.userInfoURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info: %w", err)
	}
	defer resp.Body.Close()

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
