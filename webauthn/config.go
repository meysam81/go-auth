package webauthn

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

const (
	defaultTimeout = 5 * time.Minute
	minTimeout     = 30 * time.Second
	maxTimeout     = 15 * time.Minute
)

var (
	defaultAlgorithms = []int{-8, -7, -257} // EdDSA, ES256, RS256
	dnsLabel          = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// Config configures the relying party.
type Config struct {
	RPID       string           // registrable domain or the origin's host; fixed for the life of every credential
	RPName     string           // shown by credential managers
	Origins    []string         // exact origins; https, except http://localhost for development
	Algorithms []int            // COSE; default -8, -7, -257
	Timeout    time.Duration    // default 5 min, within 30 s to 15 min
	Now        func() time.Time // nil = time.Now
}

// RP is a configured relying party.
type RP struct {
	id         string
	algorithms []int
	timeout    time.Duration
	now        func() time.Time
	wa         *gowebauthn.WebAuthn
}

// New validates cfg and returns the relying party. It refuses an origin whose
// host is neither the RP ID nor a subdomain of it.
func New(cfg Config) (*RP, error) {
	if err := validateRPID(cfg.RPID); err != nil {
		return nil, err
	}
	if cfg.RPName == "" {
		return nil, errors.New("webauthn: RPName is required")
	}
	if len(cfg.Origins) == 0 {
		return nil, errors.New("webauthn: at least one origin is required")
	}
	seen := make(map[string]bool, len(cfg.Origins))
	for _, o := range cfg.Origins {
		if seen[o] {
			return nil, fmt.Errorf("webauthn: duplicate origin %q", o)
		}
		seen[o] = true
		if err := validateOrigin(o, cfg.RPID); err != nil {
			return nil, err
		}
	}
	algs, err := resolveAlgorithms(cfg.Algorithms)
	if err != nil {
		return nil, err
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	if timeout < minTimeout || timeout > maxTimeout {
		return nil, fmt.Errorf("webauthn: timeout %s outside %s to %s", timeout, minTimeout, maxTimeout)
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	t := gowebauthn.TimeoutConfig{Enforce: true, Timeout: timeout, TimeoutUVD: timeout}
	wa, err := gowebauthn.New(&gowebauthn.Config{
		RPID:                        cfg.RPID,
		RPDisplayName:               cfg.RPName,
		RPOrigins:                   slices.Clone(cfg.Origins),
		RPTopOriginVerificationMode: protocol.TopOriginExplicitVerificationMode,
		AttestationPreference:       protocol.PreferNoAttestation,
		Timeouts:                    gowebauthn.TimeoutsConfig{Login: t, Registration: t},
		// Check 8: an ECDSA signature must be canonical DER, never BER.
		Signature: protocol.SignaturePolicy{ECDSAEncoding: protocol.ECDSASignatureEncodingDER},

		ExtensionsUnsolicitedOutputPolicy: protocol.UnsolicitedOutputPolicyReject,
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn: configuration refused: %w", err)
	}
	return &RP{id: cfg.RPID, algorithms: algs, timeout: timeout, now: now, wa: wa}, nil
}

// ID returns the relying party ID.
func (rp *RP) ID() string { return rp.id }

func validateRPID(id string) error {
	switch {
	case id == "":
		return errors.New("webauthn: RPID is required")
	case id != strings.ToLower(id):
		return fmt.Errorf("webauthn: RPID %q must be lowercase", id)
	case net.ParseIP(id) != nil:
		return fmt.Errorf("webauthn: RPID %q must not be an IP address", id)
	case strings.ContainsAny(id, ":/?#@ "):
		return fmt.Errorf("webauthn: RPID %q must be a bare domain", id)
	}
	if len(id) > 253 {
		return errors.New("webauthn: RPID is too long")
	}
	for _, l := range strings.Split(id, ".") {
		if !dnsLabel.MatchString(l) {
			return fmt.Errorf("webauthn: RPID %q is not a valid DNS name", id)
		}
	}
	return nil
}

func validateOrigin(o, rpid string) error {
	u, err := url.Parse(o)
	if err != nil {
		return fmt.Errorf("webauthn: origin %q: %w", o, err)
	}
	if scheme, _, _ := strings.Cut(o, "://"); scheme != u.Scheme {
		return fmt.Errorf("webauthn: origin %q needs a lowercase scheme", o)
	}
	host := u.Hostname()
	if !isASCII(host) {
		return fmt.Errorf("webauthn: origin %q must use the punycode form of its host", o)
	}
	if err := validatePort(o, u); err != nil {
		return err
	}
	devHTTP := u.Scheme == "http" && host == "localhost" && rpid == "localhost"
	switch {
	case u.Scheme != "https" && !devHTTP:
		return fmt.Errorf("webauthn: origin %q must be https (http only for localhost)", o)
	case u.User != nil, u.Path != "", u.RawQuery != "", u.Fragment != "", u.Opaque != "",
		strings.ContainsAny(o, "?#"), u.RawPath != "":
		return fmt.Errorf("webauthn: origin %q must be scheme, host and optional port only", o)
	case host == "" || host != strings.ToLower(host):
		return fmt.Errorf("webauthn: origin %q needs a lowercase host", o)
	case host != rpid && !strings.HasSuffix(host, "."+rpid):
		return fmt.Errorf("webauthn: origin %q is neither the RP ID nor a subdomain of it", o)
	}
	return nil
}

func resolveAlgorithms(in []int) ([]int, error) {
	if len(in) == 0 {
		return slices.Clone(defaultAlgorithms), nil
	}
	seen := make(map[int]bool, len(in))
	for _, a := range in {
		if !slices.Contains(defaultAlgorithms, a) {
			return nil, fmt.Errorf("webauthn: algorithm %d is not allowed", a)
		}
		if seen[a] {
			return nil, fmt.Errorf("webauthn: duplicate algorithm %d", a)
		}
		seen[a] = true
	}
	return slices.Clone(in), nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// validatePort refuses a port a browser never sends: empty after the colon,
// zero, above 65535 or written with a leading zero.
func validatePort(o string, u *url.URL) error {
	port := u.Port()
	if port == "" {
		if strings.HasSuffix(u.Host, ":") {
			return fmt.Errorf("webauthn: origin %q has an empty port", o)
		}
		return nil
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || port[0] == '0' {
		return fmt.Errorf("webauthn: origin %q has an invalid port", o)
	}
	return nil
}
