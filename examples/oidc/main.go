// Package main demonstrates OIDC/OAuth2 Single Sign-On (SSO) with multiple providers.
//
// This example shows how to:
//   - Configure an OIDC provider from its issuer URL via discovery
//   - Configure an OAuth2-only provider (GitHub publishes no discovery document)
//   - Start an authorization flow bound to the browser that began it
//   - Complete the callback and read the provider's verified claims
//
// The flow:
//  1. The user picks a provider on the home page
//  2. The application redirects to the provider, setting a binding cookie
//  3. The provider redirects back with an authorization code
//  4. The application exchanges the code and receives verified claims
//  5. The application resolves those claims to its own account record
//
// # Browser binding is not optional
//
// This example calls Client.GetAuthorizationURLWithBinding and
// Client.HandleCallbackWithBinding rather than the unbound pair. Without the
// binding, an attacker starts a flow, authenticates against their own account,
// and induces the victim to visit the resulting callback URL; the victim's
// browser is then signed in as the attacker, and everything the victim does next
// is recorded in an account the attacker controls (finding F-16, CWE-352). The
// binding value is issued as a cookie at authorization time and required at
// callback, so a callback that reaches a different browser fails.
//
// PKCE (finding F-17) and the ID token nonce (finding F-18) are applied by the
// library for both entry points and need no wiring here.
//
// # Identity is the application's to own
//
// Config.UserStore is left nil, which is the shape auth/oidc keeps in v2. The
// callback returns CallbackResult.UserInfo — what the provider asserted, after
// every control the library applies has passed — and this example resolves that
// to a local account itself. The deprecated find-or-create path resolved an
// account by email claim alone, which is the nOAuth account-takeover class
// (finding F-01, CVE-2023-28131).
//
// # Setup
//
// Google (https://console.cloud.google.com/apis/credentials):
//  1. Create OAuth2 credentials (Web application type)
//  2. Add redirect URI: http://localhost:8080/callback/google
//  3. export GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=...
//
// GitHub (https://github.com/settings/developers):
//  1. Create an OAuth App
//  2. Set the callback URL: http://localhost:8080/callback/github
//  3. export GITHUB_CLIENT_ID=... GITHUB_CLIENT_SECRET=...
//
// # Running the Example
//
//	go run main.go
//
// Then visit http://localhost:8080 and pick a provider.
//
// # Adding More Providers
//
// Any OIDC-capable provider is configured from its issuer URL with
// provider.NewOIDCProvider — Microsoft Entra ID, Auth0, Okta, Keycloak and the
// rest need no vendor-specific constructor. The vendor constructors in the
// provider package are deprecated for exactly that reason.
//
// # Production Usage
//
// This example uses in-memory storage which loses data on restart. For production:
//   - Implement persistent storage for accounts and OAuth state
//   - Serve over HTTPS; the binding cookie is Secure and __Host- prefixed
//   - Supply Config.HTTPClient with a dialer that refuses loopback, link-local
//     and private ranges whenever the issuer URL is operator-supplied, or that
//     URL is an SSRF primitive against the internal network (finding F-20)
//   - Establish a session or mint a JWT once the callback succeeds
//   - Decide account linking explicitly rather than by email match
package main

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	authoidc "github.com/meysam81/go-auth/auth/oidc"
	"github.com/meysam81/go-auth/middleware"
	"github.com/meysam81/go-auth/provider"
	"github.com/meysam81/go-auth/storage"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

const (
	// googleIssuerURL is all that is needed to configure Google: discovery
	// supplies the authorization, token, userinfo and JWKS endpoints.
	googleIssuerURL = "https://accounts.google.com"

	// githubUserInfoURL is GitHub's authenticated-user endpoint. GitHub
	// publishes no OIDC discovery document, so the endpoints are named here.
	githubUserInfoURL = "https://api.github.com/user"

	listenAddr = ":8080"
	baseURL    = "http://localhost" + listenAddr
)

// account is this application's own identity record. The library does not own
// it; the callback hands over verified claims and the application decides what
// they mean.
type account struct {
	ID       string
	Provider string
	Subject  string
	Email    string
	Name     string
	Username string
}

// accountStore resolves a provider assertion to a local account.
//
// The key is (provider, subject), never the email address alone. An account
// keyed on email is takeable over by any provider that can be induced to assert
// that address (finding F-01).
type accountStore struct {
	mu       sync.Mutex
	byIssuer map[string]*account
}

func newAccountStore() *accountStore {
	return &accountStore{byIssuer: make(map[string]*account)}
}

// resolve returns the account for an assertion, creating it on first sight, and
// reports whether it was created.
func (s *accountStore) resolve(info *authoidc.UserInfo) (*account, bool, error) {
	if info.Subject == "" {
		return nil, false, errors.New("provider asserted no subject identifier")
	}
	// An unverified address is not evidence of control of the mailbox. This
	// example stores it but never keys on it; a deployment that provisions or
	// links by email must refuse to do so unless EmailVerified is true.
	key := info.Provider + "\x00" + info.Subject

	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.byIssuer[key]; ok {
		return existing, false, nil
	}

	acct := &account{
		ID:       fmt.Sprintf("acct-%d", len(s.byIssuer)+1),
		Provider: info.Provider,
		Subject:  info.Subject,
		Email:    info.Email,
		Name:     info.Name,
		Username: info.Username,
	}
	s.byIssuer[key] = acct
	return acct, true, nil
}

// app holds the collaborators the handlers share.
type app struct {
	oidc     *authoidc.Client
	accounts *accountStore
	binding  middleware.SessionTokenWriter
	tmpl     *template.Template
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

// run wires the example and serves it.
func run() error {
	ctx := context.Background()

	providers, err := configureProviders(ctx)
	if err != nil {
		return err
	}
	if len(providers) == 0 {
		return errors.New("no providers configured: set GOOGLE_CLIENT_ID/SECRET or GITHUB_CLIENT_ID/SECRET")
	}

	// UserStore is deliberately absent. StateStore holds the PKCE verifier and
	// the binding digest for the lifetime of a flow, so it deserves the
	// protection a session store gets.
	oidcClient, err := authoidc.NewClient(authoidc.Config{
		Providers:   providers,
		StateStore:  storage.NewInMemoryOIDCStateStore(),
		RedirectURL: "/dashboard",
	})
	if err != nil {
		return fmt.Errorf("create OIDC client: %w", err)
	}

	// The binding cookie carries the value HandleCallbackWithBinding requires.
	// Its lifetime matches the state record's: a cookie outliving the state it
	// is paired with is a cookie with nothing left to prove.
	binding, err := middleware.NewSecureCookieWriter(middleware.SecureCookieConfig{
		CookieName: authoidc.BindingCookieName,
		MaxAge:     int(authoidc.DefaultStateTTL.Seconds()),
		SameSite:   http.SameSiteLaxMode,
	})
	if err != nil {
		return fmt.Errorf("create binding cookie writer: %w", err)
	}

	tmpl, err := parseTemplates()
	if err != nil {
		return err
	}

	a := &app{oidc: oidcClient, accounts: newAccountStore(), binding: binding, tmpl: tmpl}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", a.handleIndex)
	mux.HandleFunc("GET /login/{provider}", a.handleLogin)
	mux.HandleFunc("GET /callback/{provider}", a.handleCallback)
	mux.HandleFunc("GET /dashboard", a.handleDashboard)

	server := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	fmt.Println("Server starting on " + listenAddr)
	fmt.Println("Visit " + baseURL + " to test SSO login")
	fmt.Println("Set the redirect URI to: " + baseURL + "/callback/{provider}")

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// configureProviders builds the providers whose credentials are present.
func configureProviders(ctx context.Context) ([]authoidc.Provider, error) {
	var providers []authoidc.Provider

	googleID := os.Getenv("GOOGLE_CLIENT_ID")
	googleSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	switch {
	case googleID != "" && googleSecret != "":
		// Discovery from the issuer URL alone. provider.NewGoogleProvider is
		// deprecated: it is this call with the issuer and scopes filled in.
		google, err := provider.NewOIDCProvider(
			ctx,
			"google",
			googleIssuerURL,
			googleID,
			googleSecret,
			baseURL+"/callback/google",
			[]string{"openid", "profile", "email"},
		)
		if err != nil {
			return nil, fmt.Errorf("configure google provider: %w", err)
		}
		providers = append(providers, google)
	case googleID != "" || googleSecret != "":
		return nil, errors.New("google: set both GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET, or neither")
	default:
		log.Println("GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET unset; skipping Google")
	}

	githubID := os.Getenv("GITHUB_CLIENT_ID")
	githubSecret := os.Getenv("GITHUB_CLIENT_SECRET")
	switch {
	case githubID != "" && githubSecret != "":
		providers = append(providers, newGitHubProvider(githubID, githubSecret))
	case githubID != "" || githubSecret != "":
		return nil, errors.New("github: set both GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET, or neither")
	default:
		log.Println("GITHUB_CLIENT_ID/GITHUB_CLIENT_SECRET unset; skipping GitHub")
	}

	return providers, nil
}

// newGitHubProvider builds the OAuth2-only GitHub provider.
//
// provider.NewGitHubProvider is deprecated: a hardcoded endpoint pair, a scope
// list and a response parser are configuration the application is better placed
// to maintain than the library. Spelling it out here is also what makes the
// email-verification decision below visible.
func newGitHubProvider(clientID, clientSecret string) *provider.OAuth2Provider {
	cfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  baseURL + "/callback/github",
		Endpoint:     github.Endpoint,
		Scopes:       []string{"read:user", "user:email"},
	}

	extract := func(data map[string]interface{}) *authoidc.UserInfo {
		// GitHub's numeric id is the only stable name for the account. Without
		// it there is nothing to key on, so the response is declined rather
		// than turned into a user with an empty subject.
		id, ok := data["id"].(float64)
		if !ok {
			return nil
		}

		info := &authoidc.UserInfo{
			Subject:   fmt.Sprintf("%d", int64(id)),
			Provider:  "github",
			RawClaims: data,
		}
		if email, ok := data["email"].(string); ok {
			info.Email = email
		}
		if name, ok := data["name"].(string); ok {
			info.Name = name
		}
		if login, ok := data["login"].(string); ok {
			info.Username = login
		}
		if avatar, ok := data["avatar_url"].(string); ok {
			info.Picture = avatar
		}

		// GET /user carries no email_verified claim. GitHub only lets a
		// verified address be published as the profile email, so a non-empty
		// value is evidence; an absent one is not, and must never be reported
		// as a verified empty address. A deployment needing a hard guarantee
		// calls GET /user/emails with the user:email scope requested above and
		// takes the entry whose primary and verified fields are both true.
		info.EmailVerified = info.Email != ""
		return info
	}

	return provider.NewOAuth2Provider("github", cfg, githubUserInfoURL, extract)
}

// handleIndex lists the configured providers.
func (a *app) handleIndex(w http.ResponseWriter, r *http.Request) {
	a.render(w, "index", indexView{Providers: a.oidc.ListProviders()})
}

// handleLogin starts a bound authorization flow.
func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")

	req, err := a.oidc.GetAuthorizationURLWithBinding(r.Context(), authoidc.AuthURLOptions{
		Provider: providerName,
	})
	if err != nil {
		if errors.Is(err, authoidc.ErrProviderNotFound) {
			http.Error(w, "Unknown provider", http.StatusNotFound)
			return
		}
		// The underlying error can name the issuer, the state store, or a
		// misconfiguration. None of that belongs in a response to an
		// unauthenticated caller.
		// providerName comes from the URL path, so it is quoted: %q escapes
		// control characters and a newline cannot forge a second log line.
		//nolint:gosec // G706: the interpolated value is quoted and escaped.
		log.Printf("login: authorization URL for provider %q: %v", providerName, err)
		http.Error(w, "Could not start sign-in", http.StatusInternalServerError)
		return
	}

	// The cookie must be on the wire before the redirect, or the callback has
	// nothing to verify against.
	a.binding.Write(w, req.Binding)
	http.Redirect(w, r, req.URL, http.StatusFound)
}

// handleCallback completes the flow.
func (a *app) handleCallback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	// A provider that declines reports it here rather than with a code. Showing
	// the raw value back would reflect provider-controlled text into the page.
	if errCode := query.Get("error"); errCode != "" {
		// Provider-controlled text, quoted for the same reason as above.
		//nolint:gosec // G706: the interpolated value is quoted and escaped.
		log.Printf("callback: provider returned error %q", errCode)
		http.Error(w, "The provider declined the sign-in", http.StatusUnauthorized)
		return
	}

	state := query.Get("state")
	code := query.Get("code")
	if state == "" || code == "" {
		http.Error(w, "Malformed callback", http.StatusBadRequest)
		return
	}

	// An absent cookie yields "", which HandleCallbackWithBinding rejects for a
	// bound flow. That is the login-CSRF case: the callback arrived at a browser
	// that did not start the flow.
	bindingValue := ""
	if cookie, err := r.Cookie(authoidc.BindingCookieName); err == nil {
		bindingValue = cookie.Value
	}

	result, err := a.oidc.HandleCallbackWithBinding(r.Context(), state, code, bindingValue)

	// The flow is over either way: the state record is one-time use, so the
	// cookie has nothing left to prove and is cleared on both paths.
	a.binding.Clear(w)

	if err != nil {
		a.reportCallbackFailure(w, err)
		return
	}

	acct, isNew, err := a.accounts.resolve(result.UserInfo)
	if err != nil {
		log.Printf("callback: resolve account: %v", err)
		http.Error(w, "Could not resolve an account for this identity", http.StatusUnauthorized)
		return
	}

	// A real deployment establishes a session or mints a JWT here, then
	// redirects to result.RedirectURL.
	a.render(w, "success", successView{
		Account:       acct,
		IsNewAccount:  isNew,
		EmailVerified: result.UserInfo.EmailVerified,
		RedirectURL:   result.RedirectURL,
	})
}

// reportCallbackFailure maps a callback error to a response.
//
// Every control failure returns the same status and a generic message: which
// check failed — binding, nonce, subject, email verification, account linking —
// tells an attacker probing the endpoint exactly which one to work around.
func (a *app) reportCallbackFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, authoidc.ErrMissingBinding), errors.Is(err, authoidc.ErrBindingMismatch):
		log.Printf("callback: browser binding failed (login CSRF defense, F-16): %v", err)
	case errors.Is(err, authoidc.ErrInvalidState):
		log.Printf("callback: state unknown, expired or replayed: %v", err)
	case errors.Is(err, authoidc.ErrMissingNonce), errors.Is(err, authoidc.ErrNonceMismatch):
		log.Printf("callback: id token nonce failed (F-18): %v", err)
	case errors.Is(err, authoidc.ErrEmailNotVerified), errors.Is(err, authoidc.ErrMissingEmail),
		errors.Is(err, authoidc.ErrMissingSubject), errors.Is(err, authoidc.ErrAccountLinkRequired):
		log.Printf("callback: assertion refused (F-01): %v", err)
	default:
		log.Printf("callback: %v", err)
	}
	http.Error(w, "Authentication failed", http.StatusUnauthorized)
}

// handleDashboard is the post-login landing page.
func (a *app) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if _, err := fmt.Fprintln(w, "Welcome to your dashboard!"); err != nil {
		log.Printf("dashboard: write response: %v", err)
	}
}

// indexView is the model for the home page.
type indexView struct {
	Providers []string
}

// successView is the model for the post-callback page.
type successView struct {
	Account       *account
	IsNewAccount  bool
	EmailVerified bool
	RedirectURL   string
}

// render executes a template.
//
// html/template escapes every interpolated value by context. The previous
// version of this example concatenated provider-supplied strings into a string
// and wrote it with fmt.Fprint, which reflected whatever the provider asserted
// straight into the page.
func (a *app) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := a.tmpl.ExecuteTemplate(w, name, data); err != nil {
		// The status line is already sent, so this cannot become a 500. It is
		// logged rather than discarded: a truncated page is otherwise a silent
		// failure.
		log.Printf("render %s: %v", name, err)
	}
}

// parseTemplates compiles the two pages this example serves.
func parseTemplates() (*template.Template, error) {
	const pages = `
{{define "index"}}<!DOCTYPE html>
<html>
<head><title>OIDC/SSO Example</title></head>
<body>
	<h1>OIDC/SSO Authentication Example</h1>
	<h2>Login with:</h2>
	<ul>
	{{range .Providers}}<li><a href="/login/{{.}}">Login with {{.}}</a></li>{{end}}
	</ul>
</body>
</html>{{end}}

{{define "success"}}<!DOCTYPE html>
<html>
<head><title>Authentication Success</title></head>
<body>
	<h1>Authentication Successful</h1>
	<h2>Account</h2>
	<ul>
		<li>ID: {{.Account.ID}}</li>
		<li>Provider: {{.Account.Provider}}</li>
		<li>Subject: {{.Account.Subject}}</li>
		<li>Email: {{.Account.Email}} (verified: {{.EmailVerified}})</li>
		<li>Name: {{.Account.Name}}</li>
		<li>Username: {{.Account.Username}}</li>
		<li>New account: {{.IsNewAccount}}</li>
	</ul>
	<p><a href="/">Back to home</a></p>
</body>
</html>{{end}}
`
	tmpl, err := template.New("pages").Parse(strings.TrimSpace(pages))
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	return tmpl, nil
}
