package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCookieExtractor(t *testing.T) {
	extractor := &CookieExtractor{
		CookieName: "session_id",
	}

	// Test successful extraction
	req := httptest.NewRequest("GET", "/", nil)
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
	reqNoCookie := httptest.NewRequest("GET", "/", nil)
	_, err = extractor.Extract(reqNoCookie)
	if err != ErrUnauthorized {
		t.Fatalf("Expected ErrUnauthorized, got %v", err)
	}

	// Test wrong cookie name
	reqWrongCookie := httptest.NewRequest("GET", "/", nil)
	reqWrongCookie.AddCookie(&http.Cookie{
		Name:  "wrong_name",
		Value: "value",
	})
	_, err = extractor.Extract(reqWrongCookie)
	if err != ErrUnauthorized {
		t.Fatalf("Expected ErrUnauthorized, got %v", err)
	}
}

func TestHeaderExtractor(t *testing.T) {
	// Test with Bearer scheme
	extractor := &HeaderExtractor{
		HeaderName: "Authorization",
		Scheme:     "Bearer",
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer test-token-123")

	token, err := extractor.Extract(req)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if token != "test-token-123" {
		t.Errorf("Expected token 'test-token-123', got %s", token)
	}

	// Test missing header
	reqNoHeader := httptest.NewRequest("GET", "/", nil)
	_, err = extractor.Extract(reqNoHeader)
	if err != ErrUnauthorized {
		t.Fatalf("Expected ErrUnauthorized, got %v", err)
	}

	// Test wrong scheme
	reqWrongScheme := httptest.NewRequest("GET", "/", nil)
	reqWrongScheme.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	_, err = extractor.Extract(reqWrongScheme)
	if err != ErrUnauthorized {
		t.Fatalf("Expected ErrUnauthorized for wrong scheme, got %v", err)
	}

	// Test malformed header (no space)
	reqMalformed := httptest.NewRequest("GET", "/", nil)
	reqMalformed.Header.Set("Authorization", "Bearertoken")
	_, err = extractor.Extract(reqMalformed)
	if err != ErrUnauthorized {
		t.Fatalf("Expected ErrUnauthorized for malformed header, got %v", err)
	}

	// Test case-insensitive scheme matching
	reqLowerCase := httptest.NewRequest("GET", "/", nil)
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

	reqNoScheme := httptest.NewRequest("GET", "/", nil)
	reqNoScheme.Header.Set("X-API-Key", "api-key-value")
	token, err = extractorNoScheme.Extract(reqNoScheme)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if token != "api-key-value" {
		t.Errorf("Expected token 'api-key-value', got %s", token)
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
	reqHeader := httptest.NewRequest("GET", "/", nil)
	reqHeader.Header.Set("Authorization", "Bearer header-token")

	token, err := multiExtractor.Extract(reqHeader)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if token != "header-token" {
		t.Errorf("Expected token 'header-token', got %s", token)
	}

	// Test extraction from cookie (second extractor, fallback)
	reqCookie := httptest.NewRequest("GET", "/", nil)
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
	reqBoth := httptest.NewRequest("GET", "/", nil)
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
	reqNeither := httptest.NewRequest("GET", "/", nil)
	_, err = multiExtractor.Extract(reqNeither)
	if err != ErrUnauthorized {
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
	req := httptest.NewRequest("GET", "/", nil)

	DefaultErrorHandler(rw, req, ErrUnauthorized)

	if rw.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rw.Code)
	}
	if !contains(rw.Body.String(), "Unauthorized") {
		t.Errorf("Expected body to contain 'Unauthorized', got %s", rw.Body.String())
	}

	// Test forbidden error
	rwForbidden := httptest.NewRecorder()
	DefaultErrorHandler(rwForbidden, req, ErrForbidden)

	if rwForbidden.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", rwForbidden.Code)
	}
	if !contains(rwForbidden.Body.String(), "Forbidden") {
		t.Errorf("Expected body to contain 'Forbidden', got %s", rwForbidden.Body.String())
	}
}

func TestGetUserID(t *testing.T) {
	// Test with user ID in context
	req := httptest.NewRequest("GET", "/", nil)
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
	reqNoUser := httptest.NewRequest("GET", "/", nil)
	_, ok = GetUserID(reqNoUser)
	if ok {
		t.Error("Expected user ID to not be found")
	}
}

func TestGetSessionID(t *testing.T) {
	// Test with session ID in context
	req := httptest.NewRequest("GET", "/", nil)
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
	reqNoSession := httptest.NewRequest("GET", "/", nil)
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

// Helper function
func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && s != "" && (s == substr || len(s) >= len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsInside(s, substr)))
}

func containsInside(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
