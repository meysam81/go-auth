package provider

import (
	"strings"

	authoidc "github.com/meysam81/go-auth/auth/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/linkedin"
)

const (
	linkedinUserInfoURL = "https://api.linkedin.com/v2/userinfo"
)

// NewLinkedInProvider creates a LinkedIn OIDC provider.
// LinkedIn now supports OpenID Connect (as of 2023).
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

		if sub, ok := data["sub"].(string); ok {
			userInfo.Subject = sub
		}

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
