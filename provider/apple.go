package provider

import (
	"context"

	"golang.org/x/oauth2"
)

const (
	// appleIssuerURL is the OIDC issuer URL for Apple Sign In.
	appleIssuerURL = "https://appleid.apple.com"
)

// appleEndpoint defines the OAuth2 endpoints for Apple Sign In.
var appleEndpoint = oauth2.Endpoint{
	AuthURL:  "https://appleid.apple.com/auth/authorize",
	TokenURL: "https://appleid.apple.com/auth/token",
}

// NewAppleProvider creates an Apple Sign In OIDC provider for Apple authentication.
//
// This function creates a fully configured OIDC provider for Apple's Sign in with Apple
// service. Apple provides OIDC support with strong privacy protections and optional
// email relay features.
//
// Apple provider features:
//   - Full OIDC support with ID token verification
//   - Privacy-focused authentication with email relay option
//   - Automatic discovery of Apple's OIDC endpoints
//   - Standard scopes: openid, email, name
//   - User can choose to hide their real email address
//
// Setup instructions:
//  1. Enroll in the Apple Developer Program (developer.apple.com)
//  2. Create an App ID with "Sign in with Apple" capability enabled
//  3. Create a Services ID for your web application
//  4. Configure the return URLs (redirect URIs) for your service
//  5. Create a private key for Sign in with Apple
//  6. Generate the client secret using your private key (JWT format)
//
// Note: Apple requires the client secret to be a JWT signed with your private key,
// not a static string. You'll need to generate this JWT according to Apple's
// specifications before calling this function.
//
// Parameters:
//   - ctx: Context for OIDC discovery requests
//   - clientID: Services ID (not App ID) from Apple Developer
//   - clientSecret: JWT-based client secret signed with your private key
//   - redirectURL: Return URL registered in your Services ID configuration
//     (e.g., "https://yourapp.com/auth/apple/callback")
//
// Example:
//
//	// Note: You need to generate the client secret as a JWT
//	clientSecret := generateAppleClientSecret() // Your JWT generation logic
//	provider, err := provider.NewAppleProvider(
//	    context.Background(),
//	    "com.yourcompany.yourapp.service",
//	    clientSecret,
//	    "https://yourapp.com/auth/apple/callback",
//	)
//	if err != nil {
//	    log.Fatalf("Failed to create Apple provider: %v", err)
//	}
//
// The provider will request the following scopes by default:
//   - openid: Required for OIDC authentication
//   - email: User's email (may be a relay email if user chooses to hide it)
//   - name: User's name (only provided on first sign-in)
//
// Important notes:
//   - User name is only provided during the initial authorization, not on subsequent logins
//   - Users can choose to hide their email, in which case Apple provides a relay email
//   - The client secret must be regenerated every 6 months per Apple's requirements
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
