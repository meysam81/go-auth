package provider

import (
	"fmt"

	authoidc "github.com/meysam81/go-auth/auth/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

const (
	// githubUserInfoURL is the GitHub API endpoint for retrieving authenticated user information.
	githubUserInfoURL = "https://api.github.com/user"
)

// NewGitHubProvider creates a GitHub OAuth2 provider for GitHub authentication.
//
// This function creates an OAuth2-only provider for GitHub authentication. GitHub does
// not support the full OIDC specification, so user information is retrieved from GitHub's
// REST API rather than from ID tokens.
//
// GitHub provider features:
//   - OAuth2 authorization code flow
//   - Access to user profile via GitHub API
//   - Email addresses are always considered verified
//   - Returns GitHub username (login), name, avatar, and email
//
// Setup instructions:
//  1. Go to GitHub Settings > Developer settings > OAuth Apps (github.com/settings/developers)
//  2. Click "New OAuth App" or use an existing application
//  3. Set the Authorization callback URL to your redirect URL
//  4. Copy the Client ID and generate a Client Secret
//
// Parameters:
//   - clientID: OAuth2 client ID from GitHub OAuth App settings
//   - clientSecret: OAuth2 client secret from GitHub OAuth App settings
//   - redirectURL: The authorization callback URL registered in GitHub
//     (e.g., "https://yourapp.com/auth/github/callback")
//
// Example:
//
//	provider := provider.NewGitHubProvider(
//	    "your-github-client-id",
//	    "your-github-client-secret",
//	    "https://yourapp.com/auth/github/callback",
//	)
//
// The provider will request the following scopes by default:
//   - user:email: Access to user's email addresses
//   - read:user: Access to user's profile information
//
// Note: GitHub does not support OIDC. This provider uses OAuth2 with GitHub's REST API
// for user info retrieval. The user's GitHub ID is used as the subject identifier.
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
