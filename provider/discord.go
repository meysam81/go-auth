package provider

import (
	"fmt"

	authoidc "github.com/meysam81/go-auth/auth/oidc"
	"golang.org/x/oauth2"
)

const (
	// discordUserInfoURL is the Discord API endpoint for retrieving authenticated user information.
	discordUserInfoURL = "https://discord.com/api/users/@me"
)

// discordEndpoint defines the OAuth2 endpoints for Discord authentication.
var discordEndpoint = oauth2.Endpoint{
	AuthURL:  "https://discord.com/api/oauth2/authorize",
	TokenURL: "https://discord.com/api/oauth2/token",
}

// NewDiscordProvider creates a Discord OAuth2 provider for Discord authentication.
//
// This function creates an OAuth2-only provider for Discord authentication. Discord does
// not support the full OIDC specification, so user information is retrieved from Discord's
// REST API rather than from ID tokens.
//
// Discord provider features:
//   - OAuth2 authorization code flow
//   - Access to user profile via Discord API
//   - Returns Discord username, display name (global_name), avatar, and email
//   - Email verification status from Discord
//   - Automatic avatar URL construction from Discord CDN
//
// Setup instructions:
//  1. Go to Discord Developer Portal (discord.com/developers/applications)
//  2. Create a new application or select an existing one
//  3. Navigate to OAuth2 settings
//  4. Add your redirect URI to the list of authorized redirects
//  5. Copy the Client ID and Client Secret
//
// Parameters:
//   - clientID: Client ID from Discord application settings
//   - clientSecret: Client Secret from Discord application settings
//   - redirectURL: OAuth2 redirect URI registered in Discord application
//     (e.g., "https://yourapp.com/auth/discord/callback")
//
// Example:
//
//	provider := provider.NewDiscordProvider(
//	    "your-discord-client-id",
//	    "your-discord-client-secret",
//	    "https://yourapp.com/auth/discord/callback",
//	)
//
// The provider will request the following scopes by default:
//   - identify: Access to user's account information (username, ID, avatar)
//   - email: Access to user's email address
//
// Note: Discord does not support OIDC. This provider uses OAuth2 with Discord's REST API
// for user info retrieval. The provider automatically constructs the avatar URL from the
// Discord CDN using the user's ID and avatar hash. The display name (global_name) is
// preferred over the username when available.
func NewDiscordProvider(clientID, clientSecret, redirectURL string) *OAuth2Provider {
	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     discordEndpoint,
		Scopes:       []string{"identify", "email"},
	}

	extractFunc := func(data map[string]interface{}) *authoidc.UserInfo {
		userInfo := &authoidc.UserInfo{
			RawClaims: data,
		}

		if id, ok := data["id"].(string); ok {
			userInfo.Subject = id
		}

		if email, ok := data["email"].(string); ok {
			userInfo.Email = email
		}

		if verified, ok := data["verified"].(bool); ok {
			userInfo.EmailVerified = verified
		}

		if username, ok := data["username"].(string); ok {
			userInfo.Username = username
		}

		// Discord global_name is the display name
		if globalName, ok := data["global_name"].(string); ok {
			userInfo.Name = globalName
		} else if username, ok := data["username"].(string); ok {
			userInfo.Name = username
		}

		// Build avatar URL
		if avatar, ok := data["avatar"].(string); ok {
			if id, ok := data["id"].(string); ok {
				userInfo.Picture = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", id, avatar)
			}
		}

		return userInfo
	}

	return NewOAuth2Provider("discord", oauth2Config, discordUserInfoURL, extractFunc)
}
