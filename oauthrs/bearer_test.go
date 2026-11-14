package oauthrs_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/meysam81/go-auth/v2/oauthrs"
)

func TestBearerToken(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", 4096)
	tests := []struct {
		name, target string
		headers      []string
		want         string // empty: refused with ErrInvalidToken
	}{
		{"b64token", "/mcp", []string{"Bearer ory_at_x.Y-_~+/=="}, "ory_at_x.Y-_~+/=="},
		{"scheme is case-insensitive (RFC 7235 section 2.1)", "/mcp", []string{"bEaReR tok"}, "tok"},
		{"several spaces", "/mcp", []string{"Bearer   tok"}, "tok"},
		{"4096 bytes", "/mcp", []string{"Bearer " + long}, long},
		{"no header", "/mcp", nil, ""},
		{"basic scheme", "/mcp", []string{"Basic dXNlcjpwYXNz"}, ""},
		{"scheme only", "/mcp", []string{"Bearer"}, ""},
		{"empty token", "/mcp", []string{"Bearer "}, ""},
		{"tab separator", "/mcp", []string{"Bearer\ttok"}, ""},
		{"token with a space", "/mcp", []string{"Bearer a b"}, ""},
		{"token with a quote", "/mcp", []string{`Bearer a"b`}, ""},
		{"padding inside the token", "/mcp", []string{"Bearer a=b"}, ""},
		{"padding only", "/mcp", []string{"Bearer =="}, ""},
		{"over 4096 bytes", "/mcp", []string{"Bearer " + long + "a"}, ""},
		{"two Authorization headers (RFC 6750 section 3.1)", "/mcp", []string{"Bearer a", "Bearer a"}, ""},
		{"query token without a header (RFC 6750 section 2.3)", "/mcp?access_token=tok", nil, ""},
		{"query token ending in a semicolon", "/mcp?access_token=x;", nil, ""},
		{"query token with a broken escape", "/mcp?access_token=x%", nil, ""},
		{"query token after a semicolon pair", "/mcp?a=1;access_token=x", []string{"Bearer tok"}, ""},
		{"query token with an escaped key", "/mcp?access%5Ftoken=x", nil, ""},
		{"query that merely mentions it in a value", "/mcp?q=access_token", []string{"Bearer tok"}, "tok"},
		{"query token beside a header", "/mcp?access_token=tok", []string{"Bearer tok"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodPost, tt.target, http.NoBody)
			for _, h := range tt.headers {
				r.Header.Add("Authorization", h)
			}
			got, err := oauthrs.BearerToken(r)
			if tt.want == "" {
				if got != "" || !errors.Is(err, oauthrs.ErrInvalidToken) {
					t.Fatalf("BearerToken = %q, %v; want a refusal matching ErrInvalidToken", got, err)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("BearerToken = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

// RFC 6750 section 2.2: a form-encoded body token is never read, so the body
// stays the application's and the request authenticates as nothing.
func TestBearerToken_FormBodyTokenIsNeverRead(t *testing.T) {
	t.Parallel()
	const form = "access_token=tok"
	body := strings.NewReader(form)
	r := httptest.NewRequest(http.MethodPost, "/mcp", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if _, err := oauthrs.BearerToken(r); !errors.Is(err, oauthrs.ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
	if body.Len() != len(form) || r.PostForm != nil {
		t.Fatal("BearerToken read or parsed the body")
	}
}
