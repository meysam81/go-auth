package provider

import (
	authoidc "github.com/meysam81/go-auth/auth/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/slack"
)

const (
	slackUserInfoURL = "https://slack.com/api/users.identity"
)

// NewSlackProvider creates a Slack OAuth2 provider.
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
