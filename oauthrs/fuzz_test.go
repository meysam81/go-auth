package oauthrs_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/meysam81/go-auth/v2/oauthrs"
)

// FuzzBearerToken feeds attacker-controlled Authorization values and raw
// queries: a query naming access_token is always refused; a value is either
// refused with ErrInvalidToken alone or yields a bounded b64token that
// ends the header.
func FuzzBearerToken(f *testing.F) {
	for _, s := range []string{"Bearer tok", "bearer a.b-c_d~e+f/g==", "Basic x", "Bearer ", "Bearer a b", "Bearer =", ""} {
		f.Add(s, "")
	}
	for _, q := range []string{"access_token=x;", "access_token=x%", "a=1;access_token=x", "access%5Ftoken=x", "q=access_token"} {
		f.Add("Bearer tok", q)
	}
	f.Fuzz(func(t *testing.T, h, q string) {
		r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		r.Header.Set("Authorization", h)
		r.URL.RawQuery = q
		tok, err := oauthrs.BearerToken(r)
		for _, pair := range strings.FieldsFunc(q, func(r rune) bool { return r == '&' || r == ';' }) {
			if key, _, _ := strings.Cut(pair, "="); key == "access_token" && err == nil {
				t.Fatalf("BearerToken accepted the query token in %q", q)
			}
		}
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
