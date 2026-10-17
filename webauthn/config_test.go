package webauthn

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
)

func validConfig() Config {
	return Config{RPID: "example.test", RPName: "Example", Origins: []string{"https://app.example.test"}}
}

func TestNew_RejectsBadConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		edit func(*Config)
	}{
		{"empty RPID", func(c *Config) { c.RPID = "" }},
		{"RPID with scheme", func(c *Config) { c.RPID = "https://example.test" }},
		{"RPID with port", func(c *Config) { c.RPID = "example.test:8443" }},
		{"RPID with path", func(c *Config) { c.RPID = "example.test/x" }},
		{"RPID uppercase", func(c *Config) { c.RPID = "Example.Test" }},
		{"RPID is IP", func(c *Config) { c.RPID = "192.0.2.1"; c.Origins = []string{"https://192.0.2.1"} }},
		{"RPID bad label", func(c *Config) { c.RPID = "-example.test" }},
		{"empty RPName", func(c *Config) { c.RPName = "" }},
		{"no origins", func(c *Config) { c.Origins = nil }},
		{"trailing slash", func(c *Config) { c.Origins = []string{"https://app.example.test/"} }},
		{"path", func(c *Config) { c.Origins = []string{"https://app.example.test/x"} }},
		{"query", func(c *Config) { c.Origins = []string{"https://app.example.test?x=1"} }},
		{"fragment", func(c *Config) { c.Origins = []string{"https://app.example.test#x"} }},
		{"userinfo", func(c *Config) { c.Origins = []string{"https://u@app.example.test"} }},
		{"uppercase host", func(c *Config) { c.Origins = []string{"https://App.Example.Test"} }},
		{"http outside localhost", func(c *Config) { c.Origins = []string{"http://app.example.test"} }},
		{"foreign host", func(c *Config) { c.Origins = []string{"https://evil.test"} }},
		{"suffix without dot", func(c *Config) { c.Origins = []string{"https://badexample.test"} }},
		{"duplicate origin", func(c *Config) { c.Origins = []string{"https://example.test", "https://example.test"} }},
		{"unknown algorithm", func(c *Config) { c.Algorithms = []int{-7, -35} }},
		{"duplicate algorithm", func(c *Config) { c.Algorithms = []int{-7, -7} }},
		{"timeout too short", func(c *Config) { c.Timeout = 10 * time.Second }},
		{"timeout too long", func(c *Config) { c.Timeout = 16 * time.Minute }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := validConfig()
			tc.edit(&cfg)
			if rp, err := New(cfg); err == nil {
				t.Fatalf("New accepted a bad config: %+v", rp)
			}
		})
	}
}

func TestNew_AcceptsLocalhostHTTP(t *testing.T) {
	t.Parallel()
	rp, err := New(Config{RPID: "localhost", RPName: "Dev", Origins: []string{"http://localhost:8080"}})
	if err != nil {
		t.Fatal(err)
	}
	if rp.ID() != "localhost" {
		t.Fatalf("ID = %q", rp.ID())
	}
}

func TestNew_AcceptsSubdomainAndPort(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.Origins = []string{"https://example.test", "https://app.example.test:8443"}
	if _, err := New(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestNew_Defaults(t *testing.T) {
	t.Parallel()
	rp, err := New(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(rp.algorithms, []int{-8, -7, -257}) {
		t.Fatalf("algorithms = %v", rp.algorithms)
	}
	if rp.timeout != 5*time.Minute {
		t.Fatalf("timeout = %s", rp.timeout)
	}
	if rp.now == nil || rp.wa == nil {
		t.Fatal("now or go-webauthn instance unset")
	}
}

func TestNew_GoWebauthnPolicy(t *testing.T) {
	t.Parallel()
	rp, err := New(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	c := rp.wa.Config
	if c.RPTopOriginVerificationMode != protocol.TopOriginExplicitVerificationMode || len(c.RPTopOrigins) != 0 || c.RPAllowCrossOrigin {
		t.Fatal("cross-origin must be refused")
	}
	if c.AttestationPreference != protocol.PreferNoAttestation {
		t.Fatalf("attestation = %q", c.AttestationPreference)
	}
	if !c.Timeouts.Login.Enforce || !c.Timeouts.Registration.Enforce {
		t.Fatal("timeouts must be enforced")
	}
}

func TestRP_ID(t *testing.T) {
	t.Parallel()
	rp, err := New(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	if rp.ID() != "example.test" {
		t.Fatalf("ID = %q", rp.ID())
	}
}

func TestFailure(t *testing.T) {
	t.Parallel()
	cause := &protocol.Error{Type: "verification_error", Details: "bad"}
	err := fail(ErrInvalidCredentials, "assertion", cause)
	if !errors.Is(err, ErrInvalidCredentials) || errors.Is(err, ErrCloneSuspected) {
		t.Fatal("Is must match only its sentinel")
	}
	var pe *protocol.Error
	if !errors.As(err, &pe) || pe != cause {
		t.Fatal("As must reach the cause")
	}
	if want := "webauthn: assertion: " + cause.Error(); err.Error() != want {
		t.Fatalf("Error() = %q, want %q", err.Error(), want)
	}
	wrapped := fmt.Errorf("outer: %w", fail(ErrUnknownCredential, "handle", nil))
	if !errors.Is(wrapped, ErrUnknownCredential) {
		t.Fatal("Is through wrap")
	}
	if got := fail(ErrCloneSuspected, "counter", nil).Error(); got != "webauthn: counter" {
		t.Fatalf("Error() = %q", got)
	}
}
