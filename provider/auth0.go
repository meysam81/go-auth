package provider

import (
	"context"
	"fmt"
)

// NewAuth0Provider creates an Auth0 OIDC provider for Auth0 authentication.
//
// This function creates a fully configured OIDC provider for Auth0, a popular
// authentication and authorization platform. Auth0 provides full OIDC support
// with customizable authentication flows and user management.
//
// Auth0 provider features:
//   - Full OIDC support with ID token verification
//   - Automatic discovery of Auth0 OIDC endpoints
//   - Support for multiple authentication methods (database, social, enterprise)
//   - Customizable login pages and authentication rules
//   - Standard scopes: openid, profile, email
//
// Setup instructions:
//  1. Create an Auth0 account at auth0.com
//  2. Create a new Application (Regular Web Application type)
//  3. Configure the Allowed Callback URLs with your redirect URL
//  4. Copy the Domain, Client ID, and Client Secret from the application settings
//
// Parameters:
//   - ctx: Context for OIDC discovery requests
//   - domain: Your Auth0 tenant domain, including the region if applicable
//     Examples: "your-tenant.auth0.com", "your-tenant.us.auth0.com", "your-tenant.eu.auth0.com"
//     Do not include the "https://" prefix
//   - clientID: Client ID from Auth0 application settings
//   - clientSecret: Client Secret from Auth0 application settings
//   - redirectURL: The callback URL registered in Auth0 Allowed Callback URLs
//     (e.g., "https://yourapp.com/auth/auth0/callback")
//
// Example:
//
//	provider, err := provider.NewAuth0Provider(
//	    context.Background(),
//	    "mycompany.auth0.com",
//	    "your-auth0-client-id",
//	    "your-auth0-client-secret",
//	    "https://yourapp.com/auth/auth0/callback",
//	)
//	if err != nil {
//	    log.Fatalf("Failed to create Auth0 provider: %v", err)
//	}
//
// The provider will request the following scopes by default:
//   - openid: Required for OIDC authentication
//   - profile: User's basic profile information
//   - email: User's email address
//
// Note: Auth0 supports custom authorization servers. This implementation uses the
// default authorization server. For custom authorization servers, you may need to
// modify the issuer URL format.
func NewAuth0Provider(ctx context.Context, domain, clientID, clientSecret, redirectURL string) (*BaseOIDCProvider, error) {
	issuerURL := fmt.Sprintf("https://%s/", domain)

	scopes := []string{
		"openid",
		"profile",
		"email",
	}

	return NewOIDCProvider(ctx, "auth0", issuerURL, clientID, clientSecret, redirectURL, scopes)
}
