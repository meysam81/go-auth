package provider

import (
	"strings"

	authoidc "github.com/meysam81/go-auth/auth/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/linkedin"
)

const (
	// linkedinUserInfoURL is the LinkedIn API endpoint for retrieving user information via OIDC.
	linkedinUserInfoURL = "https://api.linkedin.com/v2/userinfo"
)

// NewLinkedInProvider creates a LinkedIn OAuth2 provider with OIDC support.
//
// This function creates an OAuth2 provider for LinkedIn authentication. As of 2023,
// LinkedIn supports OpenID Connect, but this implementation uses the OAuth2 approach
// with LinkedIn's userinfo endpoint for broader compatibility.
//
// LinkedIn provider features:
//   - OAuth2 authorization code flow with OIDC-compatible userinfo endpoint
//   - Access to user profile information
//   - Support for standard OIDC claims (email, name, picture)
//   - Email verification status
//   - Automatic username generation from name
//
// Setup instructions:
//  1. Go to LinkedIn Developers (linkedin.com/developers)
//  2. Create a new application or select an existing one
//  3. Navigate to Auth tab and add your redirect URL to "Authorized redirect URLs"
//  4. Request access to the required scopes (openid, profile, email)
//  5. Copy the Client ID and Client Secret from the Auth tab
//
// Parameters:
//   - clientID: Client ID from LinkedIn application settings
//   - clientSecret: Client Secret from LinkedIn application settings
//   - redirectURL: Redirect URL registered in LinkedIn application
//     (e.g., "https://yourapp.com/auth/linkedin/callback")
//
// Example:
//
//	provider := provider.NewLinkedInProvider(
//	    "your-linkedin-client-id",
//	    "your-linkedin-client-secret",
//	    "https://yourapp.com/auth/linkedin/callback",
//	)
//
// The provider will request the following scopes by default:
//   - openid: Required for OIDC authentication
//   - profile: User's basic profile information (name, picture)
//   - email: User's email address
//
// Note: LinkedIn does not provide a standard username field. This provider
// automatically generates a username from the user's given name and family name
// in the format "firstname.lastname" (lowercase). The provider uses LinkedIn's
// OIDC-compatible userinfo endpoint for retrieving user information.
//
// Deprecated: v2 removes the vendor-specific constructors, and this one is
// additionally out of date: LinkedIn has published an OIDC discovery document
// at "https://www.linkedin.com/oauth" since 2023, so an ID token with a
// verifiable signature, audience and nonce is available where this constructor
// gets none of them. Use [NewOIDCProvider] or [NewOIDCProviderWithClient] with
// that issuer URL and the scopes "openid", "profile", "email".
func NewLinkedInProvider(clientID, clientSecret, redirectURL string) *OAuth2Provider {
	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     linkedin.Endpoint,
		Scopes:       []string{"openid", "profile", "email"},
	}

	extractFunc := func(data map[string]interface{}) *authoidc.UserInfo {
		userInfo := &authoidc.UserInfo{
			RawClaims: data,
		}

		// Without a subject there is no stable name for this account, so the
		// response is declined rather than turned into a subject-less user.
		sub, ok := data["sub"].(string)
		if !ok || sub == "" {
			return nil
		}
		userInfo.Subject = sub

		if email, ok := data["email"].(string); ok {
			userInfo.Email = email
		}

		if emailVerified, ok := data["email_verified"].(bool); ok {
			userInfo.EmailVerified = emailVerified
		}

		if name, ok := data["name"].(string); ok {
			userInfo.Name = name
		}

		if picture, ok := data["picture"].(string); ok {
			userInfo.Picture = picture
		}

		// LinkedIn doesn't have a standard username field
		// Generate username from given_name and family_name with proper formatting
		if givenName, ok := data["given_name"].(string); ok {
			if familyName, ok := data["family_name"].(string); ok {
				userInfo.Username = strings.ToLower(givenName) + "." + strings.ToLower(familyName)
			}
		}

		return userInfo
	}

	return NewOAuth2Provider("linkedin", oauth2Config, linkedinUserInfoURL, extractFunc)
}
