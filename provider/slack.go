package provider

import (
	authoidc "github.com/meysam81/go-auth/auth/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/slack"
)

const (
	// slackUserInfoURL is the Slack API endpoint for retrieving authenticated user identity information.
	slackUserInfoURL = "https://slack.com/api/users.identity"
)

// NewSlackProvider creates a Slack OAuth2 provider for Slack authentication.
//
// This function creates an OAuth2-only provider for Slack authentication. Slack does
// not support the full OIDC specification, so user information is retrieved from Slack's
// identity API rather than from ID tokens.
//
// Slack provider features:
//   - OAuth2 authorization code flow
//   - Access to user identity via Slack API
//   - Returns user name, email, and avatar
//   - Email addresses are always considered verified
//   - Supports multiple avatar resolutions (prefers 512px, falls back to 192px)
//
// Setup instructions:
//  1. Go to Slack API (api.slack.com/apps)
//  2. Create a new Slack app or select an existing one
//  3. Navigate to OAuth & Permissions
//  4. Add your redirect URL to "Redirect URLs"
//  5. Add the required scopes under "User Token Scopes"
//  6. Copy the Client ID and Client Secret from "App Credentials"
//
// Parameters:
//   - clientID: Client ID from Slack app credentials
//   - clientSecret: Client Secret from Slack app credentials
//   - redirectURL: Redirect URL registered in Slack app OAuth settings
//     (e.g., "https://yourapp.com/auth/slack/callback")
//
// Example:
//
//	provider := provider.NewSlackProvider(
//	    "your-slack-client-id.apps.slack",
//	    "your-slack-client-secret",
//	    "https://yourapp.com/auth/slack/callback",
//	)
//
// The provider will request the following scopes by default:
//   - identity.basic: Access to basic identity information (user ID, name)
//   - identity.email: Access to user's email address
//   - identity.avatar: Access to user's avatar/profile picture
//
// Note: Slack does not support OIDC. This provider uses OAuth2 with Slack's identity
// API for user info retrieval. The response contains a nested "user" object with all
// user information. Slack emails are automatically considered verified. The provider
// prefers higher resolution avatars (512px) but falls back to 192px if unavailable.
func NewSlackProvider(clientID, clientSecret, redirectURL string) *OAuth2Provider {
	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     slack.Endpoint,
		Scopes:       []string{"identity.basic", "identity.email", "identity.avatar"},
	}

	extractFunc := func(data map[string]interface{}) *authoidc.UserInfo {
		userInfo := &authoidc.UserInfo{
			RawClaims: data,
		}

		// Slack returns nested user object
		if user, ok := data["user"].(map[string]interface{}); ok {
			if id, ok := user["id"].(string); ok {
				userInfo.Subject = id
			}

			if name, ok := user["name"].(string); ok {
				userInfo.Name = name
				userInfo.Username = name
			}

			if email, ok := user["email"].(string); ok {
				userInfo.Email = email
				userInfo.EmailVerified = true // Slack emails are verified
			}

			if image, ok := user["image_512"].(string); ok {
				userInfo.Picture = image
			} else if image, ok := user["image_192"].(string); ok {
				userInfo.Picture = image
			}
		}

		return userInfo
	}

	return NewOAuth2Provider("slack", oauth2Config, slackUserInfoURL, extractFunc)
}
