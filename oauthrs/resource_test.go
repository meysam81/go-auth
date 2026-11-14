package oauthrs_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/meysam81/go-auth/v2/oauthrs"
)

func resourceConfig() oauthrs.ResourceConfig {
	return oauthrs.ResourceConfig{
		Resource:              "https://mcp.example.test/mcp",
		AuthorizationServers:  []string{"https://auth.example.test"},
		ScopesSupported:       []string{"read", "domains:add"},
		ResourceName:          "Example",
		ResourceDocumentation: "https://example.test/docs/mcp/",
	}
}

func newResource(t *testing.T) *oauthrs.Resource {
	t.Helper()
	r, err := oauthrs.NewResource(resourceConfig())
	if err != nil {
		t.Fatalf("NewResource: %v", err)
	}
	return r
}

func TestResource_MetadataDocument(t *testing.T) {
	t.Parallel()
	r := newResource(t)
	const want = `{"resource":"https://mcp.example.test/mcp",` +
		`"authorization_servers":["https://auth.example.test"],` +
		`"scopes_supported":["read","domains:add"],"bearer_methods_supported":["header"],` +
		`"resource_name":"Example","resource_documentation":"https://example.test/docs/mcp/"}`
	doc := r.Metadata()
	if string(doc) != want {
		t.Fatalf("Metadata =\n%s\nwant\n%s", doc, want)
	}
	doc[0] = 'X'
	if string(r.Metadata()) != want {
		t.Fatal("Metadata returned the resource's own buffer")
	}
}

// RFC 9728 section 3.1: the well-known segment goes between the host and the
// path, and a lone terminating slash is dropped first.
func TestResource_MetadataURL(t *testing.T) {
	t.Parallel()
	const wk = "/.well-known/oauth-protected-resource"
	for resource, want := range map[string]string{
		"https://mcp.example.test/mcp":   "https://mcp.example.test" + wk + "/mcp",
		"https://mcp.example.test/":      "https://mcp.example.test" + wk,
		"https://mcp.example.test":       "https://mcp.example.test" + wk,
		"https://mcp.example.test:8443/": "https://mcp.example.test:8443" + wk,
		"http://localhost:8080/mcp":      "http://localhost:8080" + wk + "/mcp",
	} {
		cfg := resourceConfig()
		cfg.Resource = resource
		r, err := oauthrs.NewResource(cfg)
		if err != nil {
			t.Fatalf("NewResource(%q): %v", resource, err)
		}
		if r.MetadataURL() != want || !strings.HasSuffix(want, r.MetadataPath()) || !strings.HasPrefix(r.MetadataPath(), wk) {
			t.Errorf("%q: MetadataURL %q, MetadataPath %q; want %q", resource, r.MetadataURL(), r.MetadataPath(), want)
		}
	}
}

func TestNewResource_Refuses(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*oauthrs.ResourceConfig){
		"http resource off loopback": func(c *oauthrs.ResourceConfig) { c.Resource = "http://mcp.example.test/mcp" },
		"fragment":                   func(c *oauthrs.ResourceConfig) { c.Resource = "https://mcp.example.test/mcp#x" },
		"query":                      func(c *oauthrs.ResourceConfig) { c.Resource = "https://mcp.example.test/mcp?x=1" },
		"relative":                   func(c *oauthrs.ResourceConfig) { c.Resource = "/mcp" },
		"uppercase host":             func(c *oauthrs.ResourceConfig) { c.Resource = "https://MCP.example.test/mcp" },
		"user info":                  func(c *oauthrs.ResourceConfig) { c.Resource = "https://u@mcp.example.test/mcp" },
		"quote in the path":          func(c *oauthrs.ResourceConfig) { c.Resource = `https://mcp.example.test/m"cp` },
		"no authorization server":    func(c *oauthrs.ResourceConfig) { c.AuthorizationServers = nil },
		"authorization server http":  func(c *oauthrs.ResourceConfig) { c.AuthorizationServers = []string{"http://auth.example.test"} },
		"no scopes":                  func(c *oauthrs.ResourceConfig) { c.ScopesSupported = nil },
		"scope with a quote":         func(c *oauthrs.ResourceConfig) { c.ScopesSupported = []string{`re"ad`} },
		"scope with a space":         func(c *oauthrs.ResourceConfig) { c.ScopesSupported = []string{"read write"} },
		"duplicate scope":            func(c *oauthrs.ResourceConfig) { c.ScopesSupported = []string{"read", "read"} },
		"documentation over http":    func(c *oauthrs.ResourceConfig) { c.ResourceDocumentation = "http://example.test/docs" },
	}
	for name, edit := range tests {
		cfg := resourceConfig()
		edit(&cfg)
		if _, err := oauthrs.NewResource(cfg); err == nil {
			t.Errorf("%s: NewResource accepted %+v", name, cfg)
		}
	}
}

// A development authorization server on loopback (Hydra serve --dev) is
// accepted over http, like the resource itself; nothing else is.
func TestNewResource_AcceptsLoopbackHTTPForDevelopment(t *testing.T) {
	t.Parallel()
	cfg := resourceConfig()
	cfg.Resource, cfg.AuthorizationServers = "http://127.0.0.1:8080/mcp", []string{"http://127.0.0.1:4444/"}
	if _, err := oauthrs.NewResource(cfg); err != nil {
		t.Fatalf("NewResource: %v", err)
	}
}

func TestResource_WriteChallenge(t *testing.T) {
	t.Parallel()
	const prm = `resource_metadata="https://mcp.example.test/.well-known/oauth-protected-resource/mcp"`
	tests := []struct {
		name   string
		code   oauthrs.ErrorCode
		scopes []string
		status int
		header string
	}{
		{"invalid token names every supported scope", oauthrs.InvalidToken, nil, http.StatusUnauthorized,
			`Bearer error="invalid_token", ` + prm + `, scope="read domains:add"`},
		{"insufficient scope names what the call needs", oauthrs.InsufficientScope, []string{"domains:add"}, http.StatusForbidden,
			`Bearer error="insufficient_scope", ` + prm + `, scope="domains:add"`},
	}
	r := newResource(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := httptest.NewRecorder()
			if err := r.WriteChallenge(w, tt.code, tt.scopes...); err != nil {
				t.Fatalf("WriteChallenge: %v", err)
			}
			if w.Code != tt.status || w.Header().Get("WWW-Authenticate") != tt.header ||
				w.Header().Get("Cache-Control") != "no-store" || w.Body.Len() != 0 {
				t.Fatalf("got %d %q %q body %q; want %d %q", w.Code, w.Header().Get("WWW-Authenticate"),
					w.Header().Get("Cache-Control"), w.Body.String(), tt.status, tt.header)
			}
		})
	}
}

// No error_description is ever written, and a code or scope outside the
// resource's own set writes nothing at all.
func TestResource_WriteChallengeRefusesUnknownCodeOrScope(t *testing.T) {
	t.Parallel()
	r := newResource(t)
	for name, write := range map[string]func(http.ResponseWriter) error{
		"unknown code": func(w http.ResponseWriter) error { return r.WriteChallenge(w, "invalid_request") },
		"unknown scope": func(w http.ResponseWriter) error {
			return r.WriteChallenge(w, oauthrs.InsufficientScope, "offline_access")
		},
		"injection": func(w http.ResponseWriter) error {
			return r.WriteChallenge(w, oauthrs.InvalidToken, `read", error_description="x`)
		},
		"zero value code": func(w http.ResponseWriter) error { return r.WriteChallenge(w, "") },
	} {
		w := httptest.NewRecorder()
		if err := write(w); err == nil || w.Header().Get("WWW-Authenticate") != "" || w.Body.Len() != 0 {
			t.Errorf("%s: err = %v, header %q; want an error and nothing written", name, err, w.Header().Get("WWW-Authenticate"))
		}
	}
}
