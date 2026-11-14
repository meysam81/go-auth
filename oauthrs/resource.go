package oauthrs

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

const wellKnown = "/.well-known/oauth-protected-resource"

// ResourceConfig describes a protected resource (RFC 9728 section 2).
type ResourceConfig struct {
	Resource              string   // the identifier clients send as `resource`; https (http only on a loopback host), no query or fragment
	AuthorizationServers  []string // issuer identifiers, the same rule; at least one
	ScopesSupported       []string // RFC 6749 scope tokens; at least one, no duplicates
	ResourceName          string   // optional, shown to people
	ResourceDocumentation string   // optional https URL
}

// Resource is a validated protected resource: its metadata document and the
// challenges a refused request carries.
type Resource struct {
	metadataURL  string
	metadataPath string
	document     []byte
	scopes       []string
}

type metadataDocument struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ResourceName           string   `json:"resource_name,omitempty"`
	ResourceDocumentation  string   `json:"resource_documentation,omitempty"`
}

// NewResource validates cfg, builds the metadata document once and derives
// its URL by RFC 9728 section 3.1.
func NewResource(cfg ResourceConfig) (*Resource, error) {
	u, err := identifier("Resource", cfg.Resource, true)
	if err != nil {
		return nil, err
	}
	if len(cfg.AuthorizationServers) == 0 {
		return nil, errors.New("oauthrs: at least one authorization server is required")
	}
	for _, as := range cfg.AuthorizationServers {
		if _, err = identifier("AuthorizationServers", as, true); err != nil {
			return nil, err
		}
	}
	if cfg.ResourceDocumentation != "" {
		if _, err = identifier("ResourceDocumentation", cfg.ResourceDocumentation, false); err != nil {
			return nil, err
		}
	}
	if len(cfg.ScopesSupported) == 0 {
		return nil, errors.New("oauthrs: at least one supported scope is required")
	}
	for i, s := range cfg.ScopesSupported {
		if !scopeToken(s) || slices.Contains(cfg.ScopesSupported[:i], s) {
			return nil, fmt.Errorf("oauthrs: scope %q is not a unique RFC 6749 scope token", s)
		}
	}
	doc, err := json.Marshal(metadataDocument{
		Resource:               cfg.Resource,
		AuthorizationServers:   cfg.AuthorizationServers,
		ScopesSupported:        cfg.ScopesSupported,
		BearerMethodsSupported: []string{"header"},
		ResourceName:           cfg.ResourceName,
		ResourceDocumentation:  cfg.ResourceDocumentation,
	})
	if err != nil {
		return nil, fmt.Errorf("oauthrs: metadata document: %w", err)
	}
	path := u.EscapedPath()
	if path == "/" {
		path = ""
	}
	return &Resource{
		metadataURL:  u.Scheme + "://" + u.Host + wellKnown + path,
		metadataPath: wellKnown + path,
		document:     doc,
		scopes:       slices.Clone(cfg.ScopesSupported),
	}, nil
}

// Metadata returns a copy of the metadata document. Serve it at MetadataPath
// on the resource's host with Content-Type application/json.
func (r *Resource) Metadata() []byte { return slices.Clone(r.document) }

// MetadataURL is the document's URL, the resource_metadata a challenge names.
func (r *Resource) MetadataURL() string { return r.metadataURL }

// MetadataPath is the path MetadataURL serves on the resource's host.
func (r *Resource) MetadataPath() string { return r.metadataPath }

// ErrorCode is an RFC 6750 section 3.1 error code a challenge carries.
type ErrorCode string

const (
	// InvalidToken answers every failure of BearerToken and Verify (401).
	InvalidToken ErrorCode = "invalid_token"
	// InsufficientScope answers a verified token that lacks a scope (403).
	InsufficientScope ErrorCode = "insufficient_scope"
)

// WriteChallenge refuses the request: it sets WWW-Authenticate with the code,
// the metadata URL and a scope, and Cache-Control: no-store, then writes
// 401 for InvalidToken or 403 for InsufficientScope. Set other headers before
// calling it and write any body after. scopes defaults to every supported
// scope, and each must be one of them. No error_description is ever written.
// For an unknown code or scope it writes nothing and returns an error.
func (r *Resource) WriteChallenge(w http.ResponseWriter, code ErrorCode, scopes ...string) error {
	status := map[ErrorCode]int{InvalidToken: http.StatusUnauthorized, InsufficientScope: http.StatusForbidden}[code]
	if status == 0 {
		return fmt.Errorf("oauthrs: unknown error code %q", code)
	}
	if len(scopes) == 0 {
		scopes = r.scopes
	}
	for _, s := range scopes {
		if !slices.Contains(r.scopes, s) {
			return fmt.Errorf("oauthrs: scope %q is not supported", s)
		}
	}
	w.Header().Set("WWW-Authenticate", `Bearer error="`+string(code)+`", resource_metadata="`+
		r.metadataURL+`", scope="`+strings.Join(scopes, " ")+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	return nil
}

// identifier parses an https URL with no user info, query or fragment, in
// canonical form so the string clients compare is the one configured. With
// loopback, http is allowed on localhost, 127.0.0.1 and [::1].
func identifier(field, raw string, loopback bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("oauthrs: %s %q: %w", field, raw, err)
	}
	h := u.Hostname()
	devHTTP := loopback && u.Scheme == "http" && (h == "localhost" || h == "127.0.0.1" || h == "::1")
	if (u.Scheme != "https" && !devHTTP) || h == "" || u.User != nil || u.RawQuery != "" ||
		u.Fragment != "" || u.String() != raw || u.Host != strings.ToLower(u.Host) || strings.ContainsAny(raw, `"\`) {
		return nil, fmt.Errorf("oauthrs: %s %q must be a canonical https URL with no user info, query or fragment", field, raw)
	}
	return u, nil
}

// scopeToken reports whether s is an RFC 6749 section 3.3 scope-token.
func scopeToken(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return s != ""
}
