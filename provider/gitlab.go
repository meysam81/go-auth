package provider

import (
	"context"

	"golang.org/x/oauth2"
)

const (
	// gitlabIssuerURL is the OIDC issuer URL for GitLab.com.
	// For self-hosted GitLab instances, this would be your GitLab domain.
	gitlabIssuerURL = "https://gitlab.com"
)

// NewGitLabProvider creates a GitLab OIDC provider for GitLab.com authentication.
//
// This function creates a fully configured OIDC provider for GitLab authentication.
// GitLab provides full OIDC support for both GitLab.com and self-hosted instances.
//
// GitLab provider features:
//   - Full OIDC support with ID token verification
//   - Automatic discovery of GitLab OIDC endpoints
//   - Supports both GitLab.com and self-hosted GitLab instances
//   - Standard scopes: openid, profile, email
//   - Returns verified user profile information
//
// Setup instructions:
//  1. Log in to GitLab (gitlab.com or your self-hosted instance)
//  2. Go to User Settings > Applications
//  3. Create a new application with the "openid", "profile", and "email" scopes
//  4. Add your redirect URI to the application
//  5. Copy the Application ID and Secret
//
// Parameters:
//   - ctx: Context for OIDC discovery requests
//   - clientID: Application ID from GitLab application settings
//   - clientSecret: Secret from GitLab application settings
//   - redirectURL: Redirect URI registered in GitLab application
//     (e.g., "https://yourapp.com/auth/gitlab/callback")
//
// Example:
//
//	provider, err := provider.NewGitLabProvider(
//	    context.Background(),
//	    "your-gitlab-application-id",
//	    "your-gitlab-secret",
//	    "https://yourapp.com/auth/gitlab/callback",
//	)
//	if err != nil {
//	    log.Fatalf("Failed to create GitLab provider: %v", err)
//	}
//
// The provider will request the following scopes by default:
//   - openid: Required for OIDC authentication
//   - profile: User's basic profile information
//   - email: User's email address
//
// Note: This implementation is configured for GitLab.com. For self-hosted GitLab
// instances, you can create a custom provider using NewOIDCProvider with your
// GitLab instance URL as the issuer (e.g., "https://gitlab.yourcompany.com").
func NewGitLabProvider(ctx context.Context, clientID, clientSecret, redirectURL string) (*BaseOIDCProvider, error) {
	scopes := []string{
		"openid",
		"profile",
		"email",
	}

	endpoint := oauth2.Endpoint{
		AuthURL:  "https://gitlab.com/oauth/authorize",
		TokenURL: "https://gitlab.com/oauth/token",
	}

	provider, err := NewOIDCProvider(ctx, "gitlab", gitlabIssuerURL, clientID, clientSecret, redirectURL, scopes)
	if err != nil {
		return nil, err
	}

	// Override with GitLab's endpoint
	provider.oauth2Config.Endpoint = endpoint

	return provider, nil
}
