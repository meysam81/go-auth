package webauthn

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

func validConfig() Config {
	return Config{RPID: "example.test", RPName: "Example", Origins: []string{"https://app.example.test"}}
}

func TestNew_RejectsBadConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		edit func(*Config)
		want string // substring naming the rule that must fire
	}{
		{"empty RPID", func(c *Config) { c.RPID = "" }, "RPID is required"},
		{"RPID with scheme", func(c *Config) { c.RPID = "https://example.test" }, "bare domain"},
		{"RPID with port", func(c *Config) { c.RPID = "example.test:8443" }, "bare domain"},
		{"RPID with path", func(c *Config) { c.RPID = "example.test/x" }, "bare domain"},
		{"RPID uppercase", func(c *Config) { c.RPID = "Example.Test" }, "must be lowercase"},
		{"RPID is IP", func(c *Config) { c.RPID = "192.0.2.1"; c.Origins = []string{"https://192.0.2.1"} }, "must not be an IP"},
		{"RPID bad label", func(c *Config) { c.RPID = "-example.test" }, "valid DNS name"},
		{"empty RPName", func(c *Config) { c.RPName = "" }, "RPName is required"},
		{"no origins", func(c *Config) { c.Origins = nil }, "at least one origin"},
		{"trailing slash", func(c *Config) { c.Origins = []string{"https://app.example.test/"} }, "optional port only"},
		{"path", func(c *Config) { c.Origins = []string{"https://app.example.test/x"} }, "optional port only"},
		{"query", func(c *Config) { c.Origins = []string{"https://app.example.test?x=1"} }, "optional port only"},
		{"fragment", func(c *Config) { c.Origins = []string{"https://app.example.test#x"} }, "optional port only"},
		{"userinfo", func(c *Config) { c.Origins = []string{"https://u@app.example.test"} }, "optional port only"},
		{"uppercase host", func(c *Config) { c.Origins = []string{"https://App.Example.Test"} }, "lowercase host"},
		{"uppercase subdomain only", func(c *Config) { c.Origins = []string{"https://App.example.test"} }, "lowercase host"},
		{"uppercase scheme", func(c *Config) { c.Origins = []string{"HTTPS://app.example.test"} }, "lowercase scheme"},
		{"non-ASCII host", func(c *Config) { c.Origins = []string{"https://app.exämple.test"} }, "punycode"},
		{"empty port", func(c *Config) { c.Origins = []string{"https://app.example.test:"} }, "port"},
		{"port too large", func(c *Config) { c.Origins = []string{"https://app.example.test:99999"} }, "port"},
		{"port zero", func(c *Config) { c.Origins = []string{"https://app.example.test:0"} }, "port"},
		{"port leading zero", func(c *Config) { c.Origins = []string{"https://app.example.test:0443"} }, "port"},
		{"http outside localhost", func(c *Config) { c.Origins = []string{"http://app.example.test"} }, "must be https"},
		{"foreign host", func(c *Config) { c.Origins = []string{"https://evil.test"} }, "neither the RP ID nor a subdomain"},
		{"suffix without dot", func(c *Config) { c.Origins = []string{"https://badexample.test"} }, "neither the RP ID nor a subdomain"},
		{"duplicate origin", func(c *Config) { c.Origins = []string{"https://example.test", "https://example.test"} }, "duplicate origin"},
		{"unknown algorithm", func(c *Config) { c.Algorithms = []int{-7, -35} }, "not allowed"},
		{"duplicate algorithm", func(c *Config) { c.Algorithms = []int{-7, -7} }, "duplicate algorithm"},
		{"timeout too short", func(c *Config) { c.Timeout = 10 * time.Second }, "outside"},
		{"timeout too long", func(c *Config) { c.Timeout = 16 * time.Minute }, "outside"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := validConfig()
			tc.edit(&cfg)
			rp, err := New(cfg)
			if err == nil {
				t.Fatalf("New accepted a bad config: %+v", rp)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name the rule %q", err, tc.want)
			}
		})
	}
}

func TestNew_Boundaries(t *testing.T) {
	t.Parallel()
	for _, d := range []time.Duration{30 * time.Second, 15 * time.Minute} {
		cfg := validConfig()
		cfg.Timeout = d
		rp, err := New(cfg)
		if err != nil {
			t.Fatalf("timeout %s: %v", d, err)
		}
		c := rp.wa.Config
		for _, tc := range []gowebauthn.TimeoutConfig{c.Timeouts.Login, c.Timeouts.Registration} {
			if tc.Timeout != d || tc.TimeoutUVD != d || !tc.Enforce {
				t.Fatalf("timeout %s not pinned: %+v", d, tc)
			}
		}
	}
	cfg := validConfig()
	cfg.Algorithms = []int{-257, -7}
	rp, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(rp.algorithms, []int{-257, -7}) {
		t.Fatalf("algorithms = %v", rp.algorithms)
	}
	cfg = validConfig()
	cfg.Origins = []string{"https://app.example.test:1", "https://app.example.test:65535"}
	if _, err := New(cfg); err != nil {
		t.Fatalf("port bounds: %v", err)
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
	if c.Timeouts.Login.Timeout != 5*time.Minute || c.Timeouts.Registration.TimeoutUVD != 5*time.Minute {
		t.Fatalf("timeouts = %+v", c.Timeouts)
	}
	if c.ExtensionsUnsolicitedOutputPolicy != protocol.UnsolicitedOutputPolicyReject {
		t.Fatal("unsolicited extension outputs must be rejected")
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

func TestFailure_MatchesExactlyOneSentinel(t *testing.T) {
	t.Parallel()
	sentinels := []error{ErrInvalidCredentials, ErrUnknownCredential, ErrCloneSuspected}
	inner := fail(ErrUnknownCredential, "inner", nil)
	causes := []error{nil, errors.New("plain"), &protocol.Error{Details: "x"}, fmt.Errorf("w: %w", inner), inner}
	for _, sent := range sentinels {
		for _, cause := range causes {
			err := fail(sent, "r", cause)
			n := 0
			for _, s := range sentinels {
				if errors.Is(err, s) {
					n++
					if !errors.Is(sent, s) {
						t.Fatalf("%v with cause %v matches foreign sentinel %v", sent, cause, s)
					}
				}
			}
			if n != 1 {
				t.Fatalf("%v with cause %v matches %d sentinels", sent, cause, n)
			}
		}
	}
	var pe *protocol.Error
	if !errors.As(fail(ErrInvalidCredentials, "r", &protocol.Error{}), &pe) {
		t.Fatal("a sentinel-free cause must stay reachable")
	}
}

func TestFail_RejectsForeignSentinel(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Fatal("fail must panic for a non-sentinel")
		}
	}()
	err := fail(errors.New("other"), "r", nil)
	t.Fatalf("fail returned %v", err)
}
