// Package main demonstrates password authentication with session-cookie
// protection of subsequent requests.
//
// This example shows how to:
//   - Set up password authentication with in-memory storage
//   - Register a user and verify a password exactly once, at a sign-in endpoint
//   - Rotate the session identifier across authentication (finding F-14)
//   - Protect HTTP endpoints with SessionMiddleware and a hardened cookie
//   - Extract the authenticated principal from the request context
//
// # Why not HTTP Basic
//
// An earlier version of this example mounted middleware.BasicAuthMiddleware on
// the protected route. That middleware is deprecated (finding F-15): it runs one
// bcrypt evaluation at cost 12 — roughly 250 ms of CPU — on every request, and
// it pays that cost before it knows whether the credential is even valid, so an
// unauthenticated caller can hold the route down for the price of sending
// requests (CWE-400). HTTP Basic also has no way to carry a TOTP or WebAuthn
// assertion, so mounting it on an otherwise MFA-protected service creates a
// silent MFA bypass for that route.
//
// The shape below is the replacement the library recommends: verify the password
// once at /login, then authenticate every later request against a session
// identifier, which costs a store lookup rather than a KDF.
//
// The example serves:
//   - /                (public)  usage instructions
//   - POST /login      (public)  verifies a password, establishes a session
//   - POST /logout     (session) revokes the session and clears the cookie
//   - GET  /protected  (session) displays the authenticated principal
//
// # Running the Example
//
//	go run main.go
//
// Sign in and keep the session cookie:
//
//	curl -i -X POST http://localhost:8080/login \
//	  -d 'username=testuser' -d 'password=securepassword123'
//
// The response carries a Set-Cookie header. The cookie is marked Secure, which a
// browser honors on http://localhost because localhost is a secure context;
// curl's cookie jar is stricter, so replay the value explicitly:
//
//	curl http://localhost:8080/protected \
//	  -H 'Cookie: __Host-session=<value from Set-Cookie>'
//
// # Production Usage
//
// This example uses in-memory storage which loses data on restart. For production:
//   - Implement persistent storage using your database (PostgreSQL, MySQL, etc.)
//   - Use environment variables for sensitive data (never hardcode credentials)
//   - Serve over HTTPS: the session cookie is Secure and will not travel over
//     cleartext HTTP to any origin other than localhost
//   - Add rate limiting to the sign-in endpoint to slow credential stuffing
//   - Revoke sessions on password change; the library documents this as the
//     caller's responsibility in v1 (finding F-13)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/meysam81/go-auth/auth/basic"
	"github.com/meysam81/go-auth/middleware"
	"github.com/meysam81/go-auth/session"
	"github.com/meysam81/go-auth/storage"
)

// sessionCookieName carries the __Host- prefix, which makes a browser refuse the
// cookie unless it is Secure, host-only and Path=/. That is what stops a
// compromised sibling subdomain from planting or overwriting the session cookie.
const sessionCookieName = "__Host-session"

// maxLoginBodyBytes caps the sign-in request body. The form carries two short
// fields; anything larger is either a mistake or an attempt to make the server
// buffer on an unauthenticated caller's behalf.
const maxLoginBodyBytes = 4 << 10

// app holds the collaborators the handlers share. They are built once at
// startup: basic.NewAuthenticator performs a bcrypt evaluation of its own to
// mint the timing-equalization digest (finding F-09), so constructing one per
// request would cost what a sign-in costs.
type app struct {
	auth     *basic.Authenticator
	sessions *session.Manager
	cookies  middleware.SessionTokenWriter
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

// run wires the example and serves it. main delegates so that every failure path
// returns an error rather than calling log.Fatal from inside a helper, which
// would skip deferred cleanup.
func run() error {
	userStore := storage.NewInMemoryUserStore()
	credentialStore := storage.NewInMemoryCredentialStore()
	sessionStore := storage.NewInMemorySessionStore()

	// RequireMFAWhenEnrolled is left at its zero value, basic.EnforceMFA, so a
	// user who later confirms a second factor cannot sign in with the password
	// alone. The /login handler below reports basic.ErrMFARequired explicitly:
	// treating it as a generic failure would silently lock out every enrolled
	// user.
	auth, err := basic.NewAuthenticator(basic.Config{
		UserStore:       userStore,
		CredentialStore: credentialStore,
	})
	if err != nil {
		return fmt.Errorf("create authenticator: %w", err)
	}

	sessions, err := session.NewManager(session.Config{
		Store:      sessionStore,
		SessionTTL: 12 * time.Hour,
	})
	if err != nil {
		return fmt.Errorf("create session manager: %w", err)
	}

	// NewSecureCookieWriter sets Secure and HttpOnly and defaults SameSite to
	// Lax. A CookieWriter literal would leave all three at their zero values,
	// which is a session identifier that travels over cleartext, is readable by
	// any script on the page, and rides along on cross-site requests.
	cookies, err := middleware.NewSecureCookieWriter(middleware.SecureCookieConfig{
		CookieName: sessionCookieName,
		MaxAge:     int((12 * time.Hour).Seconds()),
	})
	if err != nil {
		return fmt.Errorf("create session cookie writer: %w", err)
	}

	a := &app{auth: auth, sessions: sessions, cookies: cookies}

	ctx := context.Background()
	user, err := a.seedDemoUser(ctx)
	if err != nil {
		return fmt.Errorf("seed demo user: %w", err)
	}
	fmt.Printf("Registered user: %s (%s)\n", user.Name, user.Email)

	sessionMiddleware := middleware.NewSessionMiddleware(middleware.SessionConfig{
		SessionManager: sessions,
		Extractor:      &middleware.CookieExtractor{CookieName: sessionCookieName},
	})

	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", a.handleLogin)
	mux.Handle("POST /logout", sessionMiddleware.Middleware(http.HandlerFunc(a.handleLogout)))
	mux.Handle("GET /protected", sessionMiddleware.Middleware(http.HandlerFunc(a.handleProtected)))
	mux.HandleFunc("GET /", a.handleIndex)

	// A bare http.ListenAndServe has no header, read or write deadline, so a
	// client that opens a connection and never completes a request holds a
	// goroutine and a file descriptor indefinitely.
	server := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	fmt.Println("Server starting on :8080")
	fmt.Println("Sign in with: curl -i -X POST http://localhost:8080/login -d 'username=testuser' -d 'password=securepassword123'")

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// seedDemoUser creates the account this example signs in as.
//
// Register is deprecated: v2 drops storage.UserStore from auth/basic and leaves
// the application to own the user row, asking the library only to hash and
// verify the password. v1 ships no replacement, so it remains the call to make
// today.
//
//nolint:staticcheck // SA1019: no v1 replacement exists; see the doc comment.
func (a *app) seedDemoUser(ctx context.Context) (*storage.User, error) {
	return a.auth.Register(ctx, basic.RegisterRequest{
		Email:    "test@example.com",
		Username: "testuser",
		Password: "securepassword123",
		Name:     "Test User",
	})
}

// handleLogin verifies the password once and establishes a session.
func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	// A sign-in form is a handful of short fields. Without a cap, ParseForm will
	// read and buffer whatever an unauthenticated caller chooses to send.
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodyBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Malformed or oversized form body", http.StatusBadRequest)
		return
	}

	username := r.PostFormValue("username")
	password := r.PostFormValue("password")
	if username == "" || password == "" {
		http.Error(w, "Both username and password are required", http.StatusBadRequest)
		return
	}

	user, err := a.auth.Authenticate(r.Context(), username, password)
	if err != nil {
		switch {
		case errors.Is(err, basic.ErrMFARequired):
			// The password was correct and a confirmed second factor exists. A
			// real deployment continues to a TOTP prompt and finishes with
			// Authenticator.AuthenticateWithTOTP; reporting this as a bad
			// password would lock out every enrolled user.
			http.Error(w, "Second factor required", http.StatusUnauthorized)
		case errors.Is(err, basic.ErrInvalidCredentials):
			// One message for both an unknown account and a wrong password. The
			// library equalizes the timing of the two paths (finding F-09); a
			// handler that distinguished them in the response would hand the
			// account-enumeration oracle straight back.
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		default:
			log.Printf("login: authenticate: %v", err)
			http.Error(w, "Sign-in temporarily unavailable", http.StatusInternalServerError)
		}
		return
	}

	sess, err := a.establishSession(r.Context(), presentedSessionID(r), user)
	if err != nil {
		// %q escapes control characters, so an identifier carrying a newline
		// cannot forge a second log line. gosec's taint analysis cannot see the
		// quoting and reports G706 regardless.
		//nolint:gosec // G706: the interpolated value is quoted and escaped.
		log.Printf("login: establish session for user %q: %v", user.ID, err)
		http.Error(w, "Sign-in temporarily unavailable", http.StatusInternalServerError)
		return
	}

	a.cookies.Write(w, sess.ID)
	writeJSON(w, signedInResponse{
		Message:  "Signed in",
		Username: user.Username,
	})
}

// establishSession binds the authenticated identity to a session identifier the
// browser did not hold before authentication.
//
// When the request already carries a session, it is rotated rather than reused:
// an identifier that survives sign-in is a session fixation vector (finding
// F-14, CWE-384), because an attacker who plants a known value in the victim's
// browser beforehand still holds a valid credential afterwards.
func (a *app) establishSession(ctx context.Context, presentedID string, user *storage.User) (*session.Session, error) {
	if presentedID != "" {
		rotated, err := a.sessions.Rotate(ctx, presentedID)
		switch {
		case err == nil:
			rotated.Data.UserID = user.ID
			rotated.Data.Email = user.Email
			rotated.Data.Provider = user.Provider
			if updateErr := a.sessions.Update(ctx, rotated.ID, rotated.Data); updateErr != nil {
				return nil, fmt.Errorf("bind identity to rotated session: %w", updateErr)
			}
			return rotated, nil
		case errors.Is(err, session.ErrSessionNotFound), errors.Is(err, session.ErrSessionExpired):
			// A stale or forged cookie value. Nothing to rotate, so fall through
			// to a fresh session; the presented identifier is never adopted.
		default:
			return nil, fmt.Errorf("rotate pre-authentication session: %w", err)
		}
	}

	sess, err := a.sessions.Create(ctx, session.CreateSessionRequest{
		UserID:   user.ID,
		Email:    user.Email,
		Provider: user.Provider,
	})
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	return sess, nil
}

// handleLogout revokes the session server-side and clears the cookie.
func (a *app) handleLogout(w http.ResponseWriter, r *http.Request) {
	sessionID, ok := middleware.GetSessionID(r)
	if !ok {
		http.Error(w, "No session in context", http.StatusInternalServerError)
		return
	}

	if err := a.sessions.Delete(r.Context(), sessionID); err != nil {
		// Clearing the cookie alone would leave the identifier live in the
		// store, so a failure here is a failed logout and is reported as one.
		log.Printf("logout: delete session: %v", err)
		http.Error(w, "Sign-out failed", http.StatusInternalServerError)
		return
	}

	a.cookies.Clear(w)
	writeJSON(w, signedInResponse{Message: "Signed out"})
}

// handleProtected renders the authenticated principal.
func (a *app) handleProtected(w http.ResponseWriter, r *http.Request) {
	data, ok := middleware.GetSessionData(r)
	if !ok {
		http.Error(w, "No session data in context", http.StatusInternalServerError)
		return
	}

	// The fields below are user-controlled. They go out through a JSON encoder,
	// which escapes them, under an explicit content type with nosniff, so no
	// browser is invited to interpret the body as HTML.
	writeJSON(w, principalResponse{
		Message:    "You are authenticated",
		UserID:     data.UserID,
		Email:      data.Email,
		SignedInAt: data.CreatedAt,
	})
}

// handleIndex documents the endpoints.
func (a *app) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	const usage = `Public endpoint - no authentication required

Endpoints:
  POST /login      username + password, sets the session cookie
  POST /logout     revokes the session (requires the cookie)
  GET  /protected  requires the session cookie

Demo credentials:
  Username: testuser
  Password: securepassword123
`
	if _, err := fmt.Fprint(w, usage); err != nil {
		log.Printf("index: write response: %v", err)
	}
}

// signedInResponse acknowledges a sign-in or sign-out.
type signedInResponse struct {
	Message  string `json:"message"`
	Username string `json:"username,omitempty"`
}

// principalResponse describes the authenticated principal.
type principalResponse struct {
	Message    string    `json:"message"`
	UserID     string    `json:"user_id"`
	Email      string    `json:"email"`
	SignedInAt time.Time `json:"signed_in_at"`
}

// writeJSON encodes a 200 response body.
//
// An encode failure arrives after the header is on the wire and so cannot be
// reported to the client; it is logged rather than discarded, because a silently
// truncated body is otherwise an unexplained client-side parse error.
func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("write JSON response: %v", err)
	}
}

// presentedSessionID returns the session identifier the browser sent, or "" when
// it sent none. A missing or empty cookie is the normal first-visit case, not an
// error worth surfacing.
func presentedSessionID(r *http.Request) string {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}
