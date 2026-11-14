package oauthrs_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/meysam81/go-auth/v2/oauthrs"
)

// FuzzBearerToken feeds attacker-controlled Authorization values: a value is
// either refused with ErrInvalidToken alone or yields a bounded b64token that
// ends the header.
func FuzzBearerToken(f *testing.F) {
	for _, s := range []string{"Bearer tok", "bearer a.b-c_d~e+f/g==", "Basic x", "Bearer ", "Bearer a b", "Bearer =", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, h string) {
		r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		r.Header.Set("Authorization", h)
		tok, err := oauthrs.BearerToken(r)
		if err != nil {
			if tok != "" || !errors.Is(err, oauthrs.ErrInvalidToken) {
				t.Fatalf("BearerToken(%q) = %q, %v", h, tok, err)
			}
			return
		}
		if tok == "" || len(tok) > 4096 || strings.ContainsAny(tok, " \t\"\\,;") || !strings.HasSuffix(h, tok) {
			t.Fatalf("BearerToken(%q) accepted %q", h, tok)
		}
	})
}
