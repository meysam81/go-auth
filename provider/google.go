package provider

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	// googleIssuerURL is the OIDC issuer URL for Google's authentication service.
	googleIssuerURL = "https://accounts.google.com"
)

// NewGoogleProvider creates a Google OIDC provider for Google Sign-In.
//
// This function creates a fully configured OIDC provider for Google authentication,
// supporting the standard OpenID Connect flow with Google's identity platform.
//
// Google provider features:
//   - Full OIDC support with ID token verification
//   - Automatic discovery of Google's OIDC endpoints
//   - Standard scopes: openid, profile, email
//   - Returns verified email addresses and profile information
//
// Setup instructions:
//  1. Create a project in Google Cloud Console (console.cloud.google.com)
//  2. Enable the Google+ API or Google Identity services
//  3. Create OAuth2 credentials (Web application type)
//  4. Add your redirect URL to authorized redirect URIs
//  5. Use the client ID and client secret from the credentials
//
// Parameters:
//   - ctx: Context for OIDC discovery requests
//   - clientID: OAuth2 client ID from Google Cloud Console
//   - clientSecret: OAuth2 client secret from Google Cloud Console
//   - redirectURL: The callback URL registered in Google Cloud Console
//     (e.g., "https://yourapp.com/auth/google/callback")
//
// Example:
//
//	provider, err := provider.NewGoogleProvider(
//	    context.Background(),
//	    "123456789.apps.googleusercontent.com",
//	    "your-client-secret",
//	    "https://yourapp.com/auth/google/callback",
//	)
//	if err != nil {
//	    log.Fatalf("Failed to create Google provider: %v", err)
//	}
//
// The provider will request the following scopes by default:
//   - openid: Required for OIDC authentication
//   - profile: User's basic profile information (name, picture)
//   - email: User's email address and verification status
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
