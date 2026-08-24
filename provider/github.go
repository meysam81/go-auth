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
//
// Deprecated: v2 removes the vendor-specific constructors. This one is a
// hardcoded endpoint pair, a scope list and a response parser, none of which
// the library is better placed to maintain than the application. GitHub
// publishes no OIDC discovery document, so the replacement is
// [NewOAuth2Provider] or [NewOAuth2ProviderWithClient] with
// [github.Endpoint], "https://api.github.com/user" and an extract function of
// your own — which is also where a deployment can call /user/emails and
// establish verification properly.
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

		// GitHub uses "id" as the unique identifier. Without it there is no
		// stable name for this account, so the response is declined rather
		// than turned into a user with an empty subject.
		id, ok := data["id"].(float64)
		if !ok {
			return nil
		}
		userInfo.Subject = fmt.Sprintf("%d", int64(id))

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

		// GET /user reports the public profile email, and GitHub only lets a
		// verified address be selected as that. It reports null for a user who
		// publishes none, and the old unconditional true then asserted that an
		// empty string was a verified address — which an account-linking
		// policy keyed on email_verified would have believed
		// (finding F-01, CVE-2023-28131, the nOAuth class).
		//
		// This endpoint carries no email_verified claim, so the inference is
		// as strong as it gets from /user alone. A deployment that needs a
		// hard guarantee must request the "user:email" scope this constructor
		// already asks for, call GET /user/emails, and take the entry whose
		// primary and verified fields are both true.
		userInfo.EmailVerified = userInfo.Email != ""

		return userInfo
	}

	return NewOAuth2Provider("github", oauth2Config, githubUserInfoURL, extractFunc)
}
