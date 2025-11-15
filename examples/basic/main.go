// Package main demonstrates basic username/password authentication with HTTP middleware.
//
// This example shows how to:
//   - Set up basic authentication with in-memory storage
//   - Register a new user with username and password
//   - Protect HTTP endpoints with Basic Auth middleware
//   - Extract user information from authenticated requests
//
// The example creates a simple HTTP server with two endpoints:
//   - / (public): Shows instructions for accessing the protected endpoint
//   - /protected (requires auth): Displays authenticated user information
//
// # Running the Example
//
// Start the server:
//
//	go run main.go
//
// Test the protected endpoint:
//
//	curl -u testuser:securepassword123 http://localhost:8080/protected
//
// Or use a browser and enter credentials when prompted:
//   - Username: testuser
//   - Password: securepassword123
//
// # Production Usage
//
// This example uses in-memory storage which loses data on restart. For production:
//   - Implement persistent storage using your database (PostgreSQL, MySQL, etc.)
//   - Use environment variables for sensitive data (never hardcode credentials)
//   - Configure appropriate password policies (length, complexity, etc.)
//   - Add rate limiting to prevent brute force attacks
//   - Use HTTPS in production to protect credentials in transit
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/meysam81/go-auth/auth/basic"
	"github.com/meysam81/go-auth/middleware"
	"github.com/meysam81/go-auth/storage"
)

func main() {
	// Initialize storage
	userStore := storage.NewInMemoryUserStore()
	credentialStore := storage.NewInMemoryCredentialStore()

	// Create basic authenticator
	auth, err := basic.NewAuthenticator(basic.Config{
		UserStore:       userStore,
		CredentialStore: credentialStore,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Register a test user
	ctx := context.Background()
	user, err := auth.Register(ctx, basic.RegisterRequest{
		Email:    "test@example.com",
		Username: "testuser",
		Password: "securepassword123",
		Name:     "Test User",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Registered user: %s (%s)\n", user.Name, user.Email)

	// Create middleware
	authMiddleware := middleware.NewBasicAuthMiddleware(middleware.BasicAuthConfig{
		Authenticator: auth,
	})

	// Protected handler
	protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := middleware.GetUser(r)
		if !ok {
			http.Error(w, "User not found in context", http.StatusInternalServerError)
			return
		}

		_, _ = fmt.Fprintf(w, "Hello, %s! You are authenticated.\n", user.Name)
		_, _ = fmt.Fprintf(w, "User ID: %s\n", user.ID)
		_, _ = fmt.Fprintf(w, "Email: %s\n", user.Email)
	})

	// Apply middleware
	http.Handle("/protected", authMiddleware.Middleware(protectedHandler))

	// Public handler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "Public endpoint - no authentication required")
		_, _ = fmt.Fprintln(w, "Try accessing /protected with Basic Auth:")
		_, _ = fmt.Fprintln(w, "  Username: testuser")
		_, _ = fmt.Fprintln(w, "  Password: securepassword123")
	})

	fmt.Println("Server starting on :8080")
	fmt.Println("Test with: curl -u testuser:securepassword123 http://localhost:8080/protected")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
