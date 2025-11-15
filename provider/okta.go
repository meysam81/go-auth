package provider

import (
	"context"
	"fmt"
)

// NewOktaProvider creates an Okta OIDC provider for Okta authentication.
//
// This function creates a fully configured OIDC provider for Okta, an enterprise-grade
// identity and access management platform. Okta provides full OIDC support with
// enterprise features like MFA, lifecycle management, and advanced security policies.
//
// Okta provider features:
//   - Full OIDC support with ID token verification
//   - Automatic discovery of Okta OIDC endpoints
//   - Uses the default authorization server (/oauth2/default)
//   - Enterprise-grade security and compliance features
//   - Standard scopes: openid, profile, email
//
// Setup instructions:
//  1. Create an Okta account at okta.com or use your organization's Okta domain
//  2. In the Okta Admin Console, go to Applications > Create App Integration
//  3. Select "OIDC - OpenID Connect" and "Web Application"
//  4. Configure the Sign-in redirect URIs with your callback URL
//  5. Copy your Okta domain, Client ID, and Client Secret
//
// Parameters:
//   - ctx: Context for OIDC discovery requests
//   - domain: Your Okta organization domain
//     Examples: "your-org.okta.com", "your-org.oktapreview.com", "your-org.okta-emea.com"
//     Do not include the "https://" prefix or any path components
//   - clientID: Client ID from Okta application settings
//   - clientSecret: Client Secret from Okta application settings
//   - redirectURL: The sign-in redirect URI registered in Okta
//     (e.g., "https://yourapp.com/auth/okta/callback")
//
// Example:
//
//	provider, err := provider.NewOktaProvider(
//	    context.Background(),
//	    "mycompany.okta.com",
//	    "your-okta-client-id",
//	    "your-okta-client-secret",
//	    "https://yourapp.com/auth/okta/callback",
//	)
//	if err != nil {
//	    log.Fatalf("Failed to create Okta provider: %v", err)
//	}
//
// The provider will request the following scopes by default:
//   - openid: Required for OIDC authentication
//   - profile: User's basic profile information
//   - email: User's email address
//
// Note: This implementation uses Okta's default authorization server (/oauth2/default).
// If you need to use a custom authorization server, you should create a custom provider
// using NewOIDCProvider with the appropriate issuer URL format:
// "https://your-domain.okta.com/oauth2/your-auth-server-id"
func NewOktaProvider(ctx context.Context, domain, clientID, clientSecret, redirectURL string) (*BaseOIDCProvider, error) {
	issuerURL := fmt.Sprintf("https://%s/oauth2/default", domain)

	scopes := []string{
		"openid",
		"profile",
		"email",
	}

	return NewOIDCProvider(ctx, "okta", issuerURL, clientID, clientSecret, redirectURL, scopes)
}
