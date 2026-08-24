package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/meysam81/go-auth/auth/jwt"
	"github.com/meysam81/go-auth/storage"
)

func TestCookieExtractor(t *testing.T) {
	extractor := &CookieExtractor{
		CookieName: "session_id",
	}

	// Test successful extraction
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.AddCookie(&http.Cookie{
		Name:  "session_id",
		Value: "test-session-123",
	})

	token, err := extractor.Extract(req)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if token != "test-session-123" {
		t.Errorf("Expected token 'test-session-123', got %s", token)
	}

	// Test missing cookie
	reqNoCookie := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	_, err = extractor.Extract(reqNoCookie)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Expected ErrUnauthorized, got %v", err)
	}

	// Test wrong cookie name
	reqWrongCookie := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	reqWrongCookie.AddCookie(&http.Cookie{
		Name:  "wrong_name",
		Value: "value",
	})
	_, err = extractor.Extract(reqWrongCookie)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Expected ErrUnauthorized, got %v", err)
	}
}

func TestHeaderExtractor(t *testing.T) {
	// Test with Bearer scheme
	extractor := &HeaderExtractor{
		HeaderName: "Authorization",
		Scheme:     "Bearer",
	}

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer test-token-123")

	token, err := extractor.Extract(req)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if token != "test-token-123" {
		t.Errorf("Expected token 'test-token-123', got %s", token)
	}

	// Test missing header
	reqNoHeader := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	_, err = extractor.Extract(reqNoHeader)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Expected ErrUnauthorized, got %v", err)
	}

	// Test wrong scheme
	reqWrongScheme := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	reqWrongScheme.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	_, err = extractor.Extract(reqWrongScheme)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Expected ErrUnauthorized for wrong scheme, got %v", err)
	}

	// Test malformed header (no space)
	reqMalformed := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	reqMalformed.Header.Set("Authorization", "Bearertoken")
	_, err = extractor.Extract(reqMalformed)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Expected ErrUnauthorized for malformed header, got %v", err)
	}

	// Test case-insensitive scheme matching
	reqLowerCase := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	reqLowerCase.Header.Set("Authorization", "bearer test-token-123")
	token, err = extractor.Extract(reqLowerCase)
	if err != nil {
		t.Fatalf("Expected no error for lowercase scheme, got %v", err)
	}
	if token != "test-token-123" {
		t.Errorf("Expected token 'test-token-123', got %s", token)
	}

	// Test without scheme
	extractorNoScheme := &HeaderExtractor{
		HeaderName: "X-API-Key",
		Scheme:     "",
	}

	// The fixture is named rather than repeated: with no scheme configured the
	// extractor must return the header value verbatim, so the assertion has to
	// compare against exactly what was set, and a bare literal on both sides
	// lets the two drift apart.
	const rawHeaderValue = "opaque-header-fixture"

	reqNoScheme := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	reqNoScheme.Header.Set("X-API-Key", rawHeaderValue)
	token, err = extractorNoScheme.Extract(reqNoScheme)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if token != rawHeaderValue {
		t.Errorf("Expected token %q, got %s", rawHeaderValue, token)
	}
}

func TestMultiExtractor(t *testing.T) {
	multiExtractor := &MultiExtractor{
		Extractors: []SessionTokenExtractor{
			&HeaderExtractor{
				HeaderName: "Authorization",
				Scheme:     "Bearer",
			},
			&CookieExtractor{
				CookieName: "session_id",
			},
		},
	}

	// Test extraction from header (first extractor)
	reqHeader := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	reqHeader.Header.Set("Authorization", "Bearer header-token")

	token, err := multiExtractor.Extract(reqHeader)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if token != "header-token" {
		t.Errorf("Expected token 'header-token', got %s", token)
	}

	// Test extraction from cookie (second extractor, fallback)
	reqCookie := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	reqCookie.AddCookie(&http.Cookie{
		Name:  "session_id",
		Value: "cookie-token",
	})

	token, err = multiExtractor.Extract(reqCookie)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if token != "cookie-token" {
		t.Errorf("Expected token 'cookie-token', got %s", token)
	}

	// Test with both present (should use first one)
	reqBoth := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	reqBoth.Header.Set("Authorization", "Bearer header-token")
	reqBoth.AddCookie(&http.Cookie{
		Name:  "session_id",
		Value: "cookie-token",
	})

	token, err = multiExtractor.Extract(reqBoth)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if token != "header-token" {
		t.Errorf("Expected first extractor's token 'header-token', got %s", token)
	}

	// Test with neither present
	reqNeither := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	_, err = multiExtractor.Extract(reqNeither)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Expected ErrUnauthorized, got %v", err)
	}
}

func TestCookieWriter(t *testing.T) {
	writer := &CookieWriter{
		CookieName: "session_id",
		Path:       "/",
		Domain:     "example.com",
		MaxAge:     3600,
		Secure:     true,
		HttpOnly:   true,
		SameSite:   http.SameSiteStrictMode,
	}

	// Test writing cookie
	rw := httptest.NewRecorder()
	writer.Write(rw, "test-session-token")

	cookies := rw.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != "session_id" {
		t.Errorf("Expected cookie name 'session_id', got %s", cookie.Name)
	}
	if cookie.Value != "test-session-token" {
		t.Errorf("Expected cookie value 'test-session-token', got %s", cookie.Value)
	}
	if cookie.Path != "/" {
		t.Errorf("Expected path '/', got %s", cookie.Path)
	}
	if cookie.Domain != "example.com" {
		t.Errorf("Expected domain 'example.com', got %s", cookie.Domain)
	}
	if cookie.MaxAge != 3600 {
		t.Errorf("Expected MaxAge 3600, got %d", cookie.MaxAge)
	}
	if !cookie.Secure {
		t.Error("Expected Secure to be true")
	}
	if !cookie.HttpOnly {
		t.Error("Expected HttpOnly to be true")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("Expected SameSite Strict, got %v", cookie.SameSite)
	}

	// Test clearing cookie
	rwClear := httptest.NewRecorder()
	writer.Clear(rwClear)

	clearCookies := rwClear.Result().Cookies()
	if len(clearCookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(clearCookies))
	}

	clearCookie := clearCookies[0]
	if clearCookie.Value != "" {
		t.Errorf("Expected empty value, got %s", clearCookie.Value)
	}
	if clearCookie.MaxAge != -1 {
		t.Errorf("Expected MaxAge -1, got %d", clearCookie.MaxAge)
	}
}

func TestDefaultErrorHandler(t *testing.T) {
	// Test unauthorized error
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)

	DefaultErrorHandler(rw, req, ErrUnauthorized)

	if rw.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rw.Code)
	}
	if !strings.Contains(rw.Body.String(), "Unauthorized") {
		t.Errorf("Expected body to contain 'Unauthorized', got %s", rw.Body.String())
	}

	// Test forbidden error
	rwForbidden := httptest.NewRecorder()
	DefaultErrorHandler(rwForbidden, req, ErrForbidden)

	if rwForbidden.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", rwForbidden.Code)
	}
	if !strings.Contains(rwForbidden.Body.String(), "Forbidden") {
		t.Errorf("Expected body to contain 'Forbidden', got %s", rwForbidden.Body.String())
	}
}

func TestGetUserID(t *testing.T) {
	// Test with user ID in context
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	ctx := context.WithValue(req.Context(), UserIDKey, "user123")
	req = req.WithContext(ctx)

	userID, ok := GetUserID(req)
	if !ok {
		t.Fatal("Expected user ID to be found")
	}
	if userID != "user123" {
		t.Errorf("Expected user ID 'user123', got %s", userID)
	}

	// Test without user ID
	reqNoUser := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	_, ok = GetUserID(reqNoUser)
	if ok {
		t.Error("Expected user ID to not be found")
	}
}

func TestGetSessionID(t *testing.T) {
	// Test with session ID in context
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	ctx := context.WithValue(req.Context(), SessionIDKey, "session123")
	req = req.WithContext(ctx)

	sessionID, ok := GetSessionID(req)
	if !ok {
		t.Fatal("Expected session ID to be found")
	}
	if sessionID != "session123" {
		t.Errorf("Expected session ID 'session123', got %s", sessionID)
	}

	// Test without session ID
	reqNoSession := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	_, ok = GetSessionID(reqNoSession)
	if ok {
		t.Error("Expected session ID to not be found")
	}
}

func TestWithUserID(t *testing.T) {
	ctx := context.Background()
	newCtx := WithUserID(ctx, "user456")

	userID, ok := newCtx.Value(UserIDKey).(string)
	if !ok {
		t.Fatal("Expected user ID to be in context")
	}
	if userID != "user456" {
		t.Errorf("Expected user ID 'user456', got %s", userID)
	}
}

func TestWithSessionID(t *testing.T) {
	ctx := context.Background()
	newCtx := WithSessionID(ctx, "session456")

	sessionID, ok := newCtx.Value(SessionIDKey).(string)
	if !ok {
		t.Fatal("Expected session ID to be in context")
	}
	if sessionID != "session456" {
		t.Errorf("Expected session ID 'session456', got %s", sessionID)
	}
}

// TestNewSecureCookieWriterDefaults pins the attributes the zero-value
// CookieWriter gets wrong: a session cookie must not travel over cleartext
// HTTP, must not be readable from script, and must not ride along on a
// cross-site request.
func TestNewSecureCookieWriterDefaults(t *testing.T) {
	writer, err := NewSecureCookieWriter(SecureCookieConfig{
		CookieName: "session_id",
		MaxAge:     3600,
	})
	if err != nil {
		t.Fatalf("NewSecureCookieWriter: %v", err)
	}

	rw := httptest.NewRecorder()
	writer.Write(rw, "token")

	cookies := rw.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	cookie := cookies[0]

	if !cookie.Secure {
		t.Error("Secure must be set")
	}
	if !cookie.HttpOnly {
		t.Error("HttpOnly must be set")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", cookie.SameSite)
	}
	if cookie.Path != "/" {
		t.Errorf("Path = %q, want /", cookie.Path)
	}
	if cookie.Domain != "" {
		t.Errorf("Domain = %q, want host-only cookie", cookie.Domain)
	}
}

// TestNewSecureCookieWriterRejectsUnsafeConfig covers the two failures a
// browser reports by silently discarding the cookie.
func TestNewSecureCookieWriterRejectsUnsafeConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  SecureCookieConfig
	}{
		{"empty name", SecureCookieConfig{}},
		{"name with separator", SecureCookieConfig{CookieName: "session id"}},
		{"name with control byte", SecureCookieConfig{CookieName: "session\x00id"}},
		{"__Host- with domain", SecureCookieConfig{CookieName: "__Host-session", Domain: "example.com"}},
		{"__Host- with path", SecureCookieConfig{CookieName: "__Host-session", Path: "/app"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewSecureCookieWriter(tt.cfg); !errors.Is(err, ErrInvalidCookieConfig) {
				t.Fatalf("err = %v, want ErrInvalidCookieConfig", err)
			}
		})
	}
}

// TestCookieWriterClearMirrorsWrite is the regression guard for a logout that
// reports success and revokes nothing: a browser keys a cookie on
// (name, domain, path), so a Clear that dropped any of them would set a second
// cookie and leave the live session identifier in place.
func TestCookieWriterClearMirrorsWrite(t *testing.T) {
	writer := &CookieWriter{
		CookieName: "session_id",
		Path:       "/app",
		Domain:     "example.com",
		MaxAge:     3600,
		Secure:     true,
		HttpOnly:   true,
		SameSite:   http.SameSiteStrictMode,
	}

	rwWrite := httptest.NewRecorder()
	writer.Write(rwWrite, "token")
	written := rwWrite.Result().Cookies()[0]

	rwClear := httptest.NewRecorder()
	writer.Clear(rwClear)
	cleared := rwClear.Result().Cookies()[0]

	if cleared.Name != written.Name {
		t.Errorf("Name = %q, want %q", cleared.Name, written.Name)
	}
	if cleared.Path != written.Path {
		t.Errorf("Path = %q, want %q", cleared.Path, written.Path)
	}
	if cleared.Domain != written.Domain {
		t.Errorf("Domain = %q, want %q", cleared.Domain, written.Domain)
	}
	if cleared.Secure != written.Secure {
		t.Errorf("Secure = %v, want %v", cleared.Secure, written.Secure)
	}
	if cleared.HttpOnly != written.HttpOnly {
		t.Errorf("HttpOnly = %v, want %v", cleared.HttpOnly, written.HttpOnly)
	}
	if cleared.SameSite != written.SameSite {
		t.Errorf("SameSite = %v, want %v", cleared.SameSite, written.SameSite)
	}
	if cleared.Value != "" {
		t.Errorf("Value = %q, want empty", cleared.Value)
	}
	if cleared.MaxAge != -1 {
		t.Errorf("MaxAge = %d, want -1", cleared.MaxAge)
	}
	// Max-Age alone is not enough for every user agent; an expiry in the past
	// must accompany it.
	if cleared.Expires.IsZero() || !cleared.Expires.Before(time.Now()) {
		t.Errorf("Expires = %v, want an instant in the past", cleared.Expires)
	}
}

// TestCookieExtractorRejectsEmptyValue: a cleared cookie is a present cookie
// with an empty value and must not be forwarded as a credential.
func TestCookieExtractorRejectsEmptyValue(t *testing.T) {
	extractor := &CookieExtractor{CookieName: "session_id"}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: ""})

	if _, err := extractor.Extract(req); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

// newTestTokenManager builds a token manager over in-memory stores.
func newTestTokenManager(t *testing.T) (*jwt.TokenManager, *storage.User) {
	t.Helper()

	userStore := storage.NewInMemoryUserStore()
	user := &storage.User{
		ID:    "u1",
		Email: "user@example.com",
	}
	if err := userStore.CreateUser(context.Background(), user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	manager, err := jwt.NewTokenManager(jwt.Config{
		UserStore:  userStore,
		SigningKey: []byte("0123456789abcdef0123456789abcdef"),
		Issuer:     "go-auth-test",
	})
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	return manager, user
}

// TestJWTMiddlewareRejectsRefreshToken is the F-02 regression guard: a refresh
// token presented as a bearer credential must not authorize a request. Reverting
// the middleware to ValidateToken alone will not fail this test — jwt pins the
// type as well — but reverting both, which is the shape of the original defect,
// does.
func TestJWTMiddlewareRejectsRefreshToken(t *testing.T) {
	manager, user := newTestTokenManager(t)

	pair, err := manager.GenerateTokenPair(context.Background(), user)
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}

	mw := NewJWTMiddleware(JWTConfig{TokenManager: manager})

	var reached bool
	handler := mw.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+pair.RefreshToken)
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	if reached {
		t.Fatal("refresh token authorized a request protected by JWTMiddleware")
	}
	if rw.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rw.Code)
	}
}

// TestJWTMiddlewareAcceptsAccessToken keeps the F-02 fix from degenerating into
// a middleware that rejects everything.
func TestJWTMiddlewareAcceptsAccessToken(t *testing.T) {
	manager, user := newTestTokenManager(t)

	pair, err := manager.GenerateTokenPair(context.Background(), user)
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}

	mw := NewJWTMiddleware(JWTConfig{TokenManager: manager})

	var (
		gotUserID string
		gotOK     bool
	)
	handler := mw.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotUserID, gotOK = GetUserID(r)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rw.Code)
	}
	if !gotOK {
		t.Error("handler ran without a user ID in its request context")
	}
	if gotUserID != user.ID {
		t.Errorf("user ID = %q, want %q", gotUserID, user.ID)
	}
}
