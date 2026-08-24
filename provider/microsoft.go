package provider

import (
	"context"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

const (
	// microsoftDiscoveryURL is where the multi-tenant metadata document lives.
	// The "common" tenant allows sign-in with any Microsoft account (personal
	// or work/school).
	microsoftDiscoveryURL = "https://login.microsoftonline.com/common/v2.0"

	// microsoftIssuerURL is the issuer the common-tenant metadata document
	// reports, verbatim, braces included. Microsoft does not report a concrete
	// issuer there because there is not one: an ID token from the common
	// endpoint carries the signing tenant's own GUID in iss. Discovery fails
	// outright unless this mismatch is declared, which is why the constructor
	// below cannot simply hand the discovery URL to NewOIDCProvider.
	microsoftIssuerURL = "https://login.microsoftonline.com/{tenantid}/v2.0"
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
// About the issuer check, and what you owe in its place:
//
// The multi-tenant "common" endpoint has no fixed issuer: every ID token it
// produces carries the signing tenant's own GUID in iss. There is therefore
// nothing to pin, and this constructor verifies the ID token's signature and
// audience but not its issuer. That is Microsoft's documented multi-tenant
// shape, not a shortcut, but it has a consequence you must handle:
//
// Any Entra ID tenant on the internet can produce a token this provider
// accepts. The provider proves the assertion came from Microsoft and was
// minted for your client ID. It does not, and cannot, prove which
// organization the user belongs to. If your application is not genuinely open
// to every Microsoft tenant, read the tid claim out of the returned user
// info's RawClaims and check it against your own allow-list before you treat
// the user as anybody.
//
// A single-tenant application should not use this constructor at all. Call
// [NewOIDCProvider] with "https://login.microsoftonline.com/<tenant-id>/v2.0"
// and the issuer is pinned for you.
//
// Deprecated: v2 removes the vendor-specific constructors. OIDC discovery
// configures any OIDC-capable provider from its issuer URL alone, so this
// function is configuration rather than logic and is not a primitive the
// library should own. Use [NewOIDCProvider] or [NewOIDCProviderWithClient]
// with the issuer URL "https://login.microsoftonline.com/<tenant-id>/v2.0",
// which additionally restores the strict issuer check this constructor has to
// give up.
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

	// Discovery is fetched from the common endpoint while the issuer is stated
	// separately, because the two disagree by design; see microsoftIssuerURL.
	// SkipIssuerCheck follows for the same reason: the real iss is per-tenant
	// and unknowable here. See the doc comment for the tid check that has to
	// take its place.
	provider, err := newOIDCProvider(ctx, "microsoft", microsoftIssuerURL, clientID, clientSecret, redirectURL, scopes, oidcProviderOptions{
		discoveryURL:    microsoftDiscoveryURL,
		skipIssuerCheck: true,
	})
	if err != nil {
		return nil, err
	}

	// Override with Microsoft's endpoint
	provider.oauth2Config = oauth2Config

	return provider, nil
}
