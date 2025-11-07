package provider

import (
	"context"

	"golang.org/x/oauth2"
)

const (
	gitlabIssuerURL = "https://gitlab.com"
)

// NewGitLabProvider creates a GitLab OIDC provider.
func NewGitLabProvider(ctx context.Context, clientID, clientSecret, redirectURL string) (*BaseOIDCProvider, error) {
	scopes := []string{
		"openid",
		"profile",
		"email",
	}

	endpoint := oauth2.Endpoint{
		AuthURL:  "https://gitlab.com/oauth/authorize",
		TokenURL: "https://gitlab.com/oauth/token",
	}

	provider, err := NewOIDCProvider(ctx, "gitlab", gitlabIssuerURL, clientID, clientSecret, redirectURL, scopes)
	if err != nil {
		return nil, err
	}

	// Override with GitLab's endpoint
	provider.oauth2Config.Endpoint = endpoint

	return provider, nil
}
