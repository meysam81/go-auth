package provider

import (
	"context"
	"fmt"
)

// NewAuth0Provider creates an Auth0 OIDC provider.
// domain should be like "your-tenant.auth0.com" or "your-tenant.us.auth0.com"
func NewAuth0Provider(ctx context.Context, domain, clientID, clientSecret, redirectURL string) (*BaseOIDCProvider, error) {
	issuerURL := fmt.Sprintf("https://%s/", domain)

	scopes := []string{
		"openid",
		"profile",
		"email",
	}

	return NewOIDCProvider(ctx, "auth0", issuerURL, clientID, clientSecret, redirectURL, scopes)
}
