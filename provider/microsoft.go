package provider

import (
	"context"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

const (
	// microsoftIssuerURL is the OIDC issuer URL for Microsoft Azure AD using the common tenant.
	// The "common" tenant allows sign-in with any Microsoft account (personal or work/school).
	microsoftIssuerURL = "https://login.microsoftonline.com/common/v2.0"
)

// NewMicrosoftProvider creates a Microsoft Azure AD OIDC provider for Microsoft account authentication.
//
// This function creates a fully configured OIDC provider for Microsoft authentication,
// supporting both personal Microsoft accounts and Azure AD organizational accounts.
// It uses the "common" tenant endpoint which accepts any Microsoft account type.
//
// Microsoft provider features:
//   - Full OIDC support with ID token verification
//   - Supports both personal and organizational Microsoft accounts
//   - Automatic discovery of Azure AD OIDC endpoints
//   - Standard scopes: openid, profile, email
//   - Returns verified email addresses and profile information
//
// Setup instructions:
//  1. Go to Azure Portal (portal.azure.com) > Azure Active Directory
//  2. Navigate to App registrations > New registration
//  3. Set a name and select supported account types (typically "Accounts in any organizational directory and personal Microsoft accounts")
//  4. Add a redirect URI (Web platform) with your callback URL
//  5. Go to Certificates & secrets > New client secret
//  6. Copy the Application (client) ID and the client secret value
//
// Parameters:
//   - ctx: Context for OIDC discovery requests
//   - clientID: Application (client) ID from Azure AD app registration
//   - clientSecret: Client secret value from Azure AD app registration
//   - redirectURL: The redirect URI registered in Azure AD
//     (e.g., "https://yourapp.com/auth/microsoft/callback")
//
// Example:
//
//	provider, err := provider.NewMicrosoftProvider(
//	    context.Background(),
//	    "12345678-1234-1234-1234-123456789012",
//	    "your-client-secret-value",
//	    "https://yourapp.com/auth/microsoft/callback",
//	)
//	if err != nil {
//	    log.Fatalf("Failed to create Microsoft provider: %v", err)
//	}
//
// The provider will request the following scopes by default:
//   - openid: Required for OIDC authentication
//   - profile: User's basic profile information
//   - email: User's email address
//
// Note: This uses the "common" tenant endpoint. For single-tenant applications,
// you may want to use a tenant-specific endpoint by modifying the issuer URL
// to include your tenant ID instead of "common".
func NewMicrosoftProvider(ctx context.Context, clientID, clientSecret, redirectURL string) (*BaseOIDCProvider, error) {
	scopes := []string{
		"openid",
		"profile",
		"email",
	}

	// Use Microsoft's Azure AD endpoint
	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     microsoft.AzureADEndpoint("common"),
		Scopes:       scopes,
	}

	provider, err := NewOIDCProvider(ctx, "microsoft", microsoftIssuerURL, clientID, clientSecret, redirectURL, scopes)
	if err != nil {
		return nil, err
	}

	// Override with Microsoft's endpoint
	provider.oauth2Config = oauth2Config

	return provider, nil
}
