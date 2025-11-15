package provider

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	googleIssuerURL = "https://accounts.google.com"
)

// NewGoogleProvider creates a Google OIDC provider.
func NewGoogleProvider(ctx context.Context, clientID, clientSecret, redirectURL string) (*BaseOIDCProvider, error) {
	scopes := []string{
		oidc.ScopeOpenID,
		"profile",
		"email",
	}

	// For Google, we can use the oauth2 package's built-in endpoint
	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     google.Endpoint,
		Scopes:       scopes,
	}

	// Create OIDC provider
	provider, err := NewOIDCProvider(ctx, "google", googleIssuerURL, clientID, clientSecret, redirectURL, scopes)
	if err != nil {
		return nil, err
	}

	// Override with Google's endpoint
	provider.oauth2Config = oauth2Config

	return provider, nil
}
