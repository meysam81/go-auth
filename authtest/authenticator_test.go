package authtest_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/meysam81/go-auth/v2/authtest"
)

// These tests drive the authenticator against bare go-webauthn, so they prove
// the authenticator itself rather than any layer built on top of it.

const (
	rpID   = "example.test"
	origin = "https://app.example.test"
)

var aaguid = [16]byte{0xa1, 0xb2, 0xc3, 0xd4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}

type user struct {
	id    []byte
	creds []webauthn.Credential
}

func (u *user) WebAuthnID() []byte                         { return u.id }
func (u *user) WebAuthnName() string                       { return "alice@example.test" }
func (u *user) WebAuthnDisplayName() string                { return "Alice" }
func (u *user) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func newRP(t *testing.T) *webauthn.WebAuthn {
	t.Helper()
	w, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: "Example",
		RPOrigins:     []string{origin},
	})
	if err != nil {
		t.Fatalf("webauthn.New: %v", err)
	}
	return w
}

func newAuthenticator(t *testing.T, cfg authtest.AuthenticatorConfig) *authtest.Authenticator {
	t.Helper()
	a, err := authtest.NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return a
}

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}

// tryRegister runs one registration ceremony and returns go-webauthn's verdict.
func tryRegister(t *testing.T, w *webauthn.WebAuthn, a *authtest.Authenticator, u *user, opts []webauthn.RegistrationOption, tampers ...authtest.Tamper) (*webauthn.Credential, error) {
	t.Helper()
	creation, session, err := w.BeginRegistration(u, opts...)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	resp, err := a.Register(marshal(t, creation.Response), origin, tampers...)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(resp)
	if err != nil {
		return nil, err
	}
	return w.CreateCredential(u, *session, parsed)
}

// register registers a with a fresh user and returns that user holding the
// new credential.
func register(t *testing.T, w *webauthn.WebAuthn, a *authtest.Authenticator, opts ...webauthn.RegistrationOption) (*user, *webauthn.Credential) {
	t.Helper()
	u := &user{id: []byte("user-handle-0123456789abcdef")}
	cred, err := tryRegister(t, w, a, u, opts)
	if err != nil {
		t.Fatalf("registration: %v", err)
	}
	u.creds = append(u.creds, *cred)
	return u, cred
}

// assertion has a sign a login challenge for u and returns the parsed response
// with the session it answers.
func assertion(t *testing.T, w *webauthn.WebAuthn, a *authtest.Authenticator, u *user, opts []webauthn.LoginOption, tampers ...authtest.Tamper) (*protocol.ParsedCredentialAssertionData, *webauthn.SessionData) {
	t.Helper()
	request, session, err := w.BeginLogin(u, opts...)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	resp, err := a.Assert(marshal(t, request.Response), origin, tampers...)
	if err != nil {
		t.Fatalf("Assert: %v", err)
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(resp)
	if err != nil {
		t.Fatalf("ParseCredentialRequestResponseBytes: %v", err)
	}
	return parsed, session
}

// login runs one login ceremony and returns go-webauthn's verdict.
func login(t *testing.T, w *webauthn.WebAuthn, a *authtest.Authenticator, u *user, opts []webauthn.LoginOption, tampers ...authtest.Tamper) (*webauthn.Credential, error) {
	t.Helper()
	parsed, session := assertion(t, w, a, u, opts, tampers...)
	return w.ValidateLogin(u, *session, parsed)
}

// keyAlgorithm returns the COSE algorithm of a stored COSE_Key.
func keyAlgorithm(t *testing.T, coseKey []byte) int64 {
	t.Helper()
	var pk webauthncose.PublicKeyData
	if err := webauthncbor.Unmarshal(coseKey, &pk); err != nil {
		t.Fatalf("decode COSE key: %v", err)
	}
	if _, err := webauthncose.ParsePublicKey(coseKey); err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	return pk.Algorithm
}

// requireProtocolError fails unless err is a go-webauthn *protocol.Error of
// the given type whose details or debug info mention want.
func requireProtocolError(t *testing.T, err error, wantType, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("err = nil, want a %q error", wantType)
	}
	var perr *protocol.Error
	if !errors.As(err, &perr) {
		t.Fatalf("err = %v (%T), want *protocol.Error", err, err)
	}
	if perr.Type != wantType {
		t.Fatalf("error type = %q (%s; %s), want %q", perr.Type, perr.Details, perr.DevInfo, wantType)
	}
	if !strings.Contains(perr.Details+" | "+perr.DevInfo, want) {
		t.Fatalf("error = %q | %q, want it to mention %q", perr.Details, perr.DevInfo, want)
	}
}

func testRegistersAndAsserts(t *testing.T, cfg authtest.AuthenticatorConfig) {
	t.Helper()
	w := newRP(t)
	a := newAuthenticator(t, cfg)
	u, cred := register(t, w, a)

	if !bytes.Equal(cred.ID, a.CredentialID()) {
		t.Errorf("credential ID = %x, want %x", cred.ID, a.CredentialID())
	}
	if got := keyAlgorithm(t, cred.PublicKey); got != int64(cfg.Algorithm) {
		t.Errorf("key algorithm = %d, want %d", got, cfg.Algorithm)
	}
	if !bytes.Equal(cred.Authenticator.AAGUID, cfg.AAGUID[:]) {
		t.Errorf("AAGUID = %x, want %x", cred.Authenticator.AAGUID, cfg.AAGUID)
	}
	if cred.Authenticator.SignCount != cfg.SignCount {
		t.Errorf("registered SignCount = %d, want %d", cred.Authenticator.SignCount, cfg.SignCount)
	}
	if cred.Flags.UserVerified != cfg.UserVerified || cred.Flags.BackupEligible != cfg.BackupEligible || cred.Flags.BackupState != cfg.BackupState {
		t.Errorf("flags = %+v, want UV=%v BE=%v BS=%v", cred.Flags, cfg.UserVerified, cfg.BackupEligible, cfg.BackupState)
	}

	for i := uint32(1); i <= 2; i++ {
		got, err := login(t, w, a, u, nil)
		if err != nil {
			t.Fatalf("login %d: %v", i, err)
		}
		if want := cfg.SignCount + i*cfg.CounterStep; got.Authenticator.SignCount != want {
			t.Errorf("login %d: SignCount = %d, want %d", i, got.Authenticator.SignCount, want)
		}
		if got.Authenticator.CloneWarning {
			t.Errorf("login %d: CloneWarning set on an advancing counter", i)
		}
		u.creds[0] = *got
	}
}

func TestAuthenticator_ES256_RegistersAndAsserts(t *testing.T) {
	t.Parallel()
	testRegistersAndAsserts(t, authtest.AuthenticatorConfig{
		Algorithm:    -7,
		AAGUID:       aaguid,
		UserVerified: true,
		CounterStep:  1,
	})
}

func TestAuthenticator_Ed25519_RegistersAndAsserts(t *testing.T) {
	t.Parallel()
	testRegistersAndAsserts(t, authtest.AuthenticatorConfig{
		Algorithm:      -8,
		AAGUID:         aaguid,
		BackupEligible: true,
		BackupState:    true,
		Discoverable:   true,
		SignCount:      7,
		CounterStep:    3,
	})
}

func TestNewAuthenticator_Algorithms(t *testing.T) {
	t.Parallel()
	tests := []struct {
		alg     int
		wantAlg int64 // 0: NewAuthenticator must refuse
	}{
		{0, -7},
		{-7, -7},
		{-8, -8},
		{-257, 0}, // RS256: valid COSE, not offered by the virtual authenticator
		{-35, 0},
		{1, 0},
	}
	for _, tt := range tests {
		a, err := authtest.NewAuthenticator(authtest.AuthenticatorConfig{Algorithm: tt.alg})
		if tt.wantAlg == 0 {
			if err == nil {
				t.Errorf("NewAuthenticator(Algorithm: %d) = nil error, want an error", tt.alg)
			}
			continue
		}
		if err != nil {
			t.Fatalf("NewAuthenticator(Algorithm: %d): %v", tt.alg, err)
		}
		_, cred := register(t, newRP(t), a)
		if got := keyAlgorithm(t, cred.PublicKey); got != tt.wantAlg {
			t.Errorf("Algorithm %d registered a %d key, want %d", tt.alg, got, tt.wantAlg)
		}
	}
}

func TestAuthenticator_TamperOrigin_FailsVerification(t *testing.T) {
	t.Parallel()
	phishing := func(c *authtest.Ceremony) { c.Origin = "https://app.example-test.evil" }

	t.Run("register", func(t *testing.T) {
		t.Parallel()
		a := newAuthenticator(t, authtest.AuthenticatorConfig{})
		_, err := tryRegister(t, newRP(t), a, &user{id: []byte("user-handle")}, nil, phishing)
		requireProtocolError(t, err, "verification_error", "Error validating origin")
	})
	t.Run("assert", func(t *testing.T) {
		t.Parallel()
		w := newRP(t)
		a := newAuthenticator(t, authtest.AuthenticatorConfig{})
		u, _ := register(t, w, a)
		_, err := login(t, w, a, u, nil, phishing)
		requireProtocolError(t, err, "verification_error", "Error validating origin")
	})
}

func TestAuthenticator_CorruptSignature_FailsSignature(t *testing.T) {
	t.Parallel()
	for _, alg := range []int{-7, -8} {
		w := newRP(t)
		a := newAuthenticator(t, authtest.AuthenticatorConfig{Algorithm: alg})
		u, _ := register(t, w, a)
		_, err := login(t, w, a, u, nil, func(c *authtest.Ceremony) { c.CorruptSignature = true })
		requireProtocolError(t, err, "invalid_signature", "")
	}
}

// TestAuthenticator_AssertionTampers_ReachTheirCheck proves each hook forges
// the attack it names: the forged value is signed, so go-webauthn refuses it at
// the matching check and never at the signature.
func TestAuthenticator_AssertionTampers_ReachTheirCheck(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		cfg      authtest.AuthenticatorConfig
		opts     []webauthn.LoginOption
		tamper   authtest.Tamper
		wantType string
		want     string
	}{
		{
			name:     "challenge from another ceremony",
			tamper:   func(c *authtest.Ceremony) { c.Challenge = base64.RawURLEncoding.EncodeToString(make([]byte, 32)) },
			wantType: "verification_error",
			want:     "Error validating challenge",
		},
		{
			name:     "registration client data replayed at sign-in",
			tamper:   func(c *authtest.Ceremony) { c.Type = "webauthn.create" },
			wantType: "verification_error",
			want:     "Error validating ceremony type",
		},
		{
			name:     "RP ID hash of another site",
			tamper:   func(c *authtest.Ceremony) { c.RPID = "evil.test" },
			wantType: "verification_error",
			want:     "RP Hash mismatch",
		},
		{
			name: "cross-origin iframe",
			tamper: func(c *authtest.Ceremony) {
				c.CrossOrigin = true
				c.TopOrigin = "https://evil.test"
			},
			wantType: "verification_error",
			want:     "cross origin",
		},
		{
			name:     "user presence flag cleared",
			tamper:   func(c *authtest.Ceremony) { c.Flags &^= byte(protocol.FlagUserPresent) },
			wantType: "verification_error",
			want:     "User presence required",
		},
		{
			name:     "verification required but not performed",
			opts:     []webauthn.LoginOption{webauthn.WithUserVerification(protocol.VerificationRequired)},
			wantType: "verification_error",
			want:     "User verification required",
		},
		{
			name:     "raw r||s ECDSA signature",
			tamper:   func(c *authtest.Ceremony) { c.RawECDSA = true },
			wantType: "invalid_signature",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := newRP(t)
			a := newAuthenticator(t, tt.cfg)
			u, _ := register(t, w, a)
			_, err := login(t, w, a, u, tt.opts, tt.tamper)
			requireProtocolError(t, err, tt.wantType, tt.want)
		})
	}
}

func TestAuthenticator_CredProps_ReportedOnlyWhenRequested(t *testing.T) {
	t.Parallel()
	yes, no := true, false
	tests := []struct {
		name         string
		discoverable bool
		request      bool
		tamper       authtest.Tamper
		want         *bool
	}{
		// go-webauthn refuses an unsolicited credProps, so success here
		// also proves it was not sent.
		{"not requested", true, false, nil, nil},
		{"requested, discoverable", true, true, nil, &yes},
		{"requested, not discoverable", false, true, nil, &no},
		{"requested but omitted", true, true, func(c *authtest.Ceremony) { c.OmitCredProps = true }, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var opts []webauthn.RegistrationOption
			if tt.request {
				opts = append(opts, webauthn.WithExtensions(webauthn.WithExtensionCredProps()))
			}
			a := newAuthenticator(t, authtest.AuthenticatorConfig{Discoverable: tt.discoverable})
			cred, err := tryRegister(t, newRP(t), a, &user{id: []byte("user-handle")}, opts, tt.tamper)
			if err != nil {
				t.Fatalf("registration: %v", err)
			}
			got := cred.Extensions.RK
			if (got == nil) != (tt.want == nil) || (got != nil && *got != *tt.want) {
				t.Errorf("credProps.rk = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthenticator_UserHandle_SentOnlyWhenDiscoverable(t *testing.T) {
	t.Parallel()
	for _, discoverable := range []bool{true, false} {
		w := newRP(t)
		a := newAuthenticator(t, authtest.AuthenticatorConfig{Discoverable: discoverable})
		u, _ := register(t, w, a)
		parsed, session := assertion(t, w, a, u, nil)

		want := []byte(nil)
		if discoverable {
			want = u.id
		}
		if !bytes.Equal(parsed.Response.UserHandle, want) {
			t.Errorf("discoverable=%v: userHandle = %q, want %q", discoverable, parsed.Response.UserHandle, want)
		}
		if _, err := w.ValidateLogin(u, *session, parsed); err != nil {
			t.Errorf("discoverable=%v: ValidateLogin: %v", discoverable, err)
		}
	}
}

func TestAuthenticator_SetSignCount_ProducesCounterRegression(t *testing.T) {
	t.Parallel()
	w := newRP(t)
	a := newAuthenticator(t, authtest.AuthenticatorConfig{SignCount: 10, CounterStep: 1})
	u, _ := register(t, w, a)

	// A tampered counter is a one-ceremony forgery: the next assertion still
	// advances from the authenticator's own counter.
	if _, err := login(t, w, a, u, nil, func(c *authtest.Ceremony) { c.SignCount = 0 }); err != nil {
		t.Fatalf("tampered login: %v", err)
	}
	got, err := login(t, w, a, u, nil)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if got.Authenticator.SignCount != 12 || got.Authenticator.CloneWarning {
		t.Fatalf("SignCount = %d (clone warning %v), want 12 without a warning", got.Authenticator.SignCount, got.Authenticator.CloneWarning)
	}
	u.creds[0] = *got

	a.SetSignCount(3)
	got, err = login(t, w, a, u, nil)
	if err != nil {
		t.Fatalf("login after SetSignCount: %v", err)
	}
	if !got.Authenticator.CloneWarning {
		t.Errorf("counter 4 after stored 12: CloneWarning = false, want true")
	}
}

func TestAuthenticator_SignatureTampers_RefusedWhereNothingIsSigned(t *testing.T) {
	t.Parallel()
	w := newRP(t)
	es256 := newAuthenticator(t, authtest.AuthenticatorConfig{Algorithm: -7})
	creation, _, err := w.BeginRegistration(&user{id: []byte("user-handle")})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	options := marshal(t, creation.Response)
	for name, tamper := range map[string]authtest.Tamper{
		"CorruptSignature": func(c *authtest.Ceremony) { c.CorruptSignature = true },
		"RawECDSA":         func(c *authtest.Ceremony) { c.RawECDSA = true },
	} {
		if _, rerr := es256.Register(options, origin, tamper); rerr == nil {
			t.Errorf("Register with %s = nil error; attestation none signs nothing", name)
		}
	}

	ed25519 := newAuthenticator(t, authtest.AuthenticatorConfig{Algorithm: -8})
	u, _ := register(t, w, ed25519)
	request, _, err := w.BeginLogin(u)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	raw := func(c *authtest.Ceremony) { c.RawECDSA = true }
	if _, err = ed25519.Assert(marshal(t, request.Response), origin, raw); err == nil {
		t.Error("Ed25519 Assert with RawECDSA = nil error, want an error")
	}
}

func TestAuthenticator_RefusesOptionsWithoutChallenge(t *testing.T) {
	t.Parallel()
	a := newAuthenticator(t, authtest.AuthenticatorConfig{})
	// The legacy navigator.credentials wrapper, not the publicKey object.
	wrapped := []byte(`{"publicKey":{"challenge":"AAAAAAAAAAAAAAAAAAAAAA","rpId":"example.test"}}`)
	if _, err := a.Register(wrapped, origin); err == nil {
		t.Error("Register(wrapped options) = nil error, want an error")
	}
	if _, err := a.Assert(wrapped, origin); err == nil {
		t.Error("Assert(wrapped options) = nil error, want an error")
	}
}
