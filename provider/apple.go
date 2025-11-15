package provider

import (
	"context"

	"golang.org/x/oauth2"
)

const (
	appleIssuerURL = "https://appleid.apple.com"
)

var appleEndpoint = oauth2.Endpoint{
	AuthURL:  "https://appleid.apple.com/auth/authorize",
	TokenURL: "https://appleid.apple.com/auth/token",
}

// NewAppleProvider creates an Apple Sign In OIDC provider.
func NewAppleProvider(ctx context.Context, clientID, clientSecret, redirectURL string) (*BaseOIDCProvider, error) {
	scopes := []string{
		"openid",
		"email",
		"name",
	}

	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     appleEndpoint,
		Scopes:       scopes,
	}

	provider, err := NewOIDCProvider(ctx, "apple", appleIssuerURL, clientID, clientSecret, redirectURL, scopes)
	if err != nil {
		return nil, err
	}

	// Override with Apple's endpoint
	provider.oauth2Config = oauth2Config

	return provider, nil
}
