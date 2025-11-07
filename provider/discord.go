package provider

import (
	"fmt"

	authoidc "github.com/meysam81/go-auth/auth/oidc"
	"golang.org/x/oauth2"
)

const (
	discordUserInfoURL = "https://discord.com/api/users/@me"
)

var discordEndpoint = oauth2.Endpoint{
	AuthURL:  "https://discord.com/api/oauth2/authorize",
	TokenURL: "https://discord.com/api/oauth2/token",
}

// NewDiscordProvider creates a Discord OAuth2 provider.
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
