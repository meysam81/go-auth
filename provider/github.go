package provider

import (
	"fmt"

	authoidc "github.com/meysam81/go-auth/auth/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

const (
	githubUserInfoURL = "https://api.github.com/user"
)

// NewGitHubProvider creates a GitHub OAuth2 provider.
// Note: GitHub doesn't support OIDC, so this uses OAuth2 + user API.
func NewGitHubProvider(clientID, clientSecret, redirectURL string) *OAuth2Provider {
	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     github.Endpoint,
		Scopes:       []string{"user:email", "read:user"},
	}

	extractFunc := func(data map[string]interface{}) *authoidc.UserInfo {
		userInfo := &authoidc.UserInfo{
			RawClaims: data,
		}

		// GitHub uses "id" as the unique identifier
		if id, ok := data["id"].(float64); ok {
			userInfo.Subject = fmt.Sprintf("%d", int64(id))
		}

		if email, ok := data["email"].(string); ok {
			userInfo.Email = email
		}

		if name, ok := data["name"].(string); ok {
			userInfo.Name = name
		}

		if login, ok := data["login"].(string); ok {
			userInfo.Username = login
		}

		if avatarURL, ok := data["avatar_url"].(string); ok {
			userInfo.Picture = avatarURL
		}

		// GitHub emails from API are always verified
		userInfo.EmailVerified = true

		return userInfo
	}

	return NewOAuth2Provider("github", oauth2Config, githubUserInfoURL, extractFunc)
}
