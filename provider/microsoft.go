package provider

import (
	"context"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

const (
	microsoftIssuerURL = "https://login.microsoftonline.com/common/v2.0"
)

// NewMicrosoftProvider creates a Microsoft Azure AD OIDC provider.
func NewMicrosoftProvider(ctx context.Context, clientID, clientSecret, redirectURL string) (*BaseOIDCProvider, error) {
	scopes := []string{
		"openid",
		"profile",
		"email",
	}

	// Use Microsoft's Azure AD endpoint
	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     microsoft.AzureADEndpoint("common"),
		Scopes:       scopes,
	}

	provider, err := NewOIDCProvider(ctx, "microsoft", microsoftIssuerURL, clientID, clientSecret, redirectURL, scopes)
	if err != nil {
		return nil, err
	}

	// Override with Microsoft's endpoint
	provider.oauth2Config = oauth2Config

	return provider, nil
}
