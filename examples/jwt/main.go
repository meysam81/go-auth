// Package main demonstrates JWT authentication usage.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/meysam81/go-auth/auth/jwt"
	"github.com/meysam81/go-auth/middleware"
	"github.com/meysam81/go-auth/storage"
)

func main() {
	// Initialize storage
	userStore := storage.NewInMemoryUserStore()
	tokenStore := storage.NewInMemoryTokenStore()

	// Create a test user
	ctx := context.Background()
	user := &storage.User{
		ID:       "user123",
		Email:    "test@example.com",
		Username: "testuser",
		Name:     "Test User",
		Provider: "local",
	}
	if err := userStore.CreateUser(ctx, user); err != nil {
		log.Fatal(err)
	}

	// Create JWT manager
	signingKey := []byte("your-secret-key-keep-it-secret")
	tokenManager, err := jwt.NewTokenManager(jwt.Config{
		UserStore:       userStore,
		TokenStore:      tokenStore,
		SigningKey:      signingKey,
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		Issuer:          "example-app",
	})
	if err != nil {
		log.Fatal(err)
	}

	// Create middleware
	authMiddleware := middleware.NewJWTMiddleware(middleware.JWTConfig{
		TokenManager: tokenManager,
	})

	// Login handler - generates JWT tokens
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// In a real app, you'd verify credentials here
		tokenPair, err := tokenManager.GenerateTokenPair(r.Context(), user)
		if err != nil {
			http.Error(w, "Failed to generate tokens", http.StatusInternalServerError)
			log.Printf("Error generating tokens: %v", err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenPair)
	})

	// Refresh token handler
	http.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		tokenPair, err := tokenManager.RefreshAccessToken(r.Context(), req.RefreshToken)
		if err != nil {
			http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenPair)
	})

	// Protected handler
	protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := middleware.GetClaims(r)
		if !ok {
			http.Error(w, "Claims not found in context", http.StatusInternalServerError)
			return
		}

		response := map[string]interface{}{
			"message":  "Hello from protected endpoint",
			"user_id":  claims.UserID,
			"email":    claims.Email,
			"provider": claims.Provider,
			"issued_at": claims.IssuedAt.Time,
			"expires_at": claims.ExpiresAt.Time,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// Apply middleware to protected route
	http.Handle("/protected", authMiddleware.Middleware(protectedHandler))

	// Home handler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "JWT Authentication Example")
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "Endpoints:")
		fmt.Fprintln(w, "  POST /login      - Get access and refresh tokens")
		fmt.Fprintln(w, "  POST /refresh    - Refresh access token")
		fmt.Fprintln(w, "  GET  /protected  - Protected endpoint (requires Bearer token)")
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "Example usage:")
		fmt.Fprintln(w, "  1. Login: curl -X POST http://localhost:8080/login")
		fmt.Fprintln(w, "  2. Access: curl -H 'Authorization: Bearer <token>' http://localhost:8080/protected")
	})

	fmt.Println("Server starting on :8080")
	fmt.Println("Try: curl -X POST http://localhost:8080/login")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
