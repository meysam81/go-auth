package provider

import (
	"context"
	"fmt"
)

// NewOktaProvider creates an Okta OIDC provider.
// domain should be like "your-org.okta.com" or "your-org.oktapreview.com"
func NewOktaProvider(ctx context.Context, domain, clientID, clientSecret, redirectURL string) (*BaseOIDCProvider, error) {
	issuerURL := fmt.Sprintf("https://%s/oauth2/default", domain)

	scopes := []string{
		"openid",
		"profile",
		"email",
	}

	return NewOIDCProvider(ctx, "okta", issuerURL, clientID, clientSecret, redirectURL, scopes)
}
