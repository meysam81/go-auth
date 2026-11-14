package outbound_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/meysam81/go-auth/v2/internal/outbound"
)

func TestClient_RefusesAnUnboundedClient(t *testing.T) {
	t.Parallel()
	for _, c := range []*http.Client{nil, {}} {
		if _, err := outbound.Client(c); err == nil {
			t.Errorf("Client(%v) = nil error, want a refusal", c)
		}
	}
}

// A redirect would carry a bearer token or an admin call to a host nobody
// configured (CWE-601), so it is answered as itself and never followed.
func TestDo_NeverFollowsARedirect(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	t.Cleanup(target.Close)
	origin := httptest.NewServer(http.RedirectHandler(target.URL, http.StatusTemporaryRedirect))
	t.Cleanup(origin.Close)
	c, err := outbound.Client(&http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, origin.URL, strings.NewReader("token=t"))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := outbound.Do(c, req, 1024)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Status != http.StatusTemporaryRedirect || hits.Load() != 0 {
		t.Fatalf("status %d, target hits %d; want 307 and 0", resp.Status, hits.Load())
	}
}

func TestDo_RefusesABodyOverTheCap(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte(strings.Repeat("a", 11))); err != nil {
			t.Errorf("write: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := outbound.Client(&http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	for limit, wantErr := range map[int64]bool{10: true, 11: false} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, http.NoBody)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		if _, err := outbound.Do(c, req, limit); (err != nil) != wantErr {
			t.Errorf("Do with limit %d: err = %v, want error %v", limit, err, wantErr)
		}
	}
}

func TestParseURL(t *testing.T) {
	t.Parallel()
	for raw, ok := range map[string]bool{
		"http://hydra-admin:4445":        true,
		"https://auth.example.test/base": true,
		"":                               false,
		"/admin":                         false,
		"ftp://auth.example.test":        false,
		"https://u:p@auth.example.test":  false,
		"https://auth.example.test?x=1":  false,
		"https://auth.example.test#x":    false,
		"https://":                       false,
	} {
		if _, err := outbound.ParseURL(raw); (err == nil) != ok {
			t.Errorf("ParseURL(%q) err = %v, want ok %v", raw, err, ok)
		}
	}
}

// A transport failure keeps its cause for logs but never the URL's query,
// which may carry a login or consent challenge.
func TestDo_TransportErrorDropsTheQuery(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()
	c, err := outbound.Client(&http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/admin?login_challenge=secret-ch", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if _, err := outbound.Do(c, req, 1024); err == nil || strings.Contains(err.Error(), "secret-ch") {
		t.Fatalf("Do err = %v; want a failure without the query", err)
	}
}
