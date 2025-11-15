// Package main demonstrates basic authentication usage.
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

		fmt.Fprintf(w, "Hello, %s! You are authenticated.\n", user.Name)
		fmt.Fprintf(w, "User ID: %s\n", user.ID)
		fmt.Fprintf(w, "Email: %s\n", user.Email)
	})

	// Apply middleware
	http.Handle("/protected", authMiddleware.Middleware(protectedHandler))

	// Public handler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Public endpoint - no authentication required")
		fmt.Fprintln(w, "Try accessing /protected with Basic Auth:")
		fmt.Fprintln(w, "  Username: testuser")
		fmt.Fprintln(w, "  Password: securepassword123")
	})

	fmt.Println("Server starting on :8080")
	fmt.Println("Test with: curl -u testuser:securepassword123 http://localhost:8080/protected")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
