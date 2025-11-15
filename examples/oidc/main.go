// Package main demonstrates OIDC/SSO authentication usage.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	authoidc "github.com/meysam81/go-auth/auth/oidc"
	"github.com/meysam81/go-auth/provider"
	"github.com/meysam81/go-auth/storage"
)

func main() {
	// Get configuration from environment
	googleClientID := os.Getenv("GOOGLE_CLIENT_ID")
	googleClientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	githubClientID := os.Getenv("GITHUB_CLIENT_ID")
	githubClientSecret := os.Getenv("GITHUB_CLIENT_SECRET")

	if googleClientID == "" || googleClientSecret == "" {
		log.Println("Warning: GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET not set")
		log.Println("Set these environment variables to test Google OAuth")
	}

	if githubClientID == "" || githubClientSecret == "" {
		log.Println("Warning: GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET not set")
		log.Println("Set these environment variables to test GitHub OAuth")
	}

	// Initialize storage
	userStore := storage.NewInMemoryUserStore()
	stateStore := storage.NewInMemoryOIDCStateStore()

	ctx := context.Background()

	// Create providers
	var providers []authoidc.Provider

	if googleClientID != "" {
		googleProvider, err := provider.NewGoogleProvider(
			ctx,
			googleClientID,
			googleClientSecret,
			"http://localhost:8080/callback/google",
		)
		if err != nil {
			log.Fatal(err)
		}
		providers = append(providers, googleProvider)
	}

	if githubClientID != "" {
		githubProvider := provider.NewGitHubProvider(
			githubClientID,
			githubClientSecret,
			"http://localhost:8080/callback/github",
		)
		providers = append(providers, githubProvider)
	}

	if len(providers) == 0 {
		log.Fatal("No providers configured. Set environment variables for at least one provider.")
	}

	// Create OIDC client
	oidcClient, err := authoidc.NewClient(authoidc.Config{
		Providers:   providers,
		UserStore:   userStore,
		StateStore:  stateStore,
		RedirectURL: "/dashboard",
	})
	if err != nil {
		log.Fatal(err)
	}

	// Home page - shows login links
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		html := `
<!DOCTYPE html>
<html>
<head><title>OIDC/SSO Example</title></head>
<body>
	<h1>OIDC/SSO Authentication Example</h1>
	<h2>Login with:</h2>
	<ul>
`
		for _, p := range oidcClient.ListProviders() {
			html += fmt.Sprintf(`<li><a href="/login/%s">Login with %s</a></li>`, p, p)
		}

		html += `
	</ul>
</body>
</html>
`
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, html)
	})

	// Login handler - initiates OAuth flow
	http.HandleFunc("/login/", func(w http.ResponseWriter, r *http.Request) {
		providerName := r.URL.Path[len("/login/"):]

		authURL, err := oidcClient.GetAuthorizationURL(r.Context(), authoidc.AuthURLOptions{
			Provider: providerName,
		})
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to get auth URL: %v", err), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
	})

	// Callback handler - handles OAuth callback
	http.HandleFunc("/callback/", func(w http.ResponseWriter, r *http.Request) {
		state := r.URL.Query().Get("state")
		code := r.URL.Query().Get("code")

		if code == "" {
			http.Error(w, "No authorization code received", http.StatusBadRequest)
			return
		}

		result, err := oidcClient.HandleCallback(r.Context(), state, code)
		if err != nil {
			http.Error(w, fmt.Sprintf("Authentication failed: %v", err), http.StatusUnauthorized)
			return
		}

		// In a real app, you'd create a session or JWT token here
		html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head><title>Authentication Success</title></head>
<body>
	<h1>Authentication Successful!</h1>
	<h2>User Information:</h2>
	<ul>
		<li>ID: %s</li>
		<li>Email: %s</li>
		<li>Name: %s</li>
		<li>Username: %s</li>
		<li>Provider: %s</li>
		<li>New User: %v</li>
	</ul>
	<p><a href="/">Back to home</a></p>
</body>
</html>
`, result.User.ID, result.User.Email, result.User.Name, result.User.Username, result.User.Provider, result.IsNewUser)

		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, html)
	})

	// Dashboard (post-login redirect)
	http.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "Welcome to your dashboard!")
	})

	fmt.Println("Server starting on :8080")
	fmt.Println("Visit http://localhost:8080 to test SSO login")
	fmt.Println("")
	fmt.Println("Make sure to configure OAuth apps in your provider:")
	fmt.Println("  Google: https://console.cloud.google.com/apis/credentials")
	fmt.Println("  GitHub: https://github.com/settings/developers")
	fmt.Println("")
	fmt.Println("Set redirect URI to: http://localhost:8080/callback/{provider}")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
