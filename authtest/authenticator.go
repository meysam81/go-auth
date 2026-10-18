package authtest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"sync"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// AuthenticatorConfig describes a virtual authenticator. The zero value is an
// ES256 authenticator that reports user presence only and whose counter stays
// at 0.
type AuthenticatorConfig struct {
	// Algorithm is the COSE algorithm of the credential key: -7 (ES256, the
	// default when zero) or -8 (Ed25519). NewAuthenticator refuses any other
	// value, -257 (RS256) included.
	Algorithm int

	// AAGUID is reported in the attested credential data at registration.
	AAGUID [16]byte

	// BackupEligible sets the BE flag (0x08) on every ceremony.
	BackupEligible bool

	// BackupState sets the BS flag (0x10) on every ceremony. It is not checked
	// against BackupEligible, so BS without BE is a configuration a test can use
	// to produce that invalid combination.
	BackupState bool

	// UserVerified sets the UV flag (0x04) on every ceremony. The flag comes from
	// here and never from the options' userVerification, so a test can withhold
	// user verification from a ceremony that requires it.
	UserVerified bool

	// SignCount is the initial signature counter, reported at registration.
	SignCount uint32

	// CounterStep is added to the counter for each assertion. Zero models a
	// synced passkey, whose counter never moves.
	CounterStep uint32

	// Discoverable makes the credential client-side discoverable: it is
	// reported as credProps.rk when the creation options request credProps,
	// and assertions carry the user handle.
	Discoverable bool
}

// Ceremony is what the authenticator is about to sign, in the form a [Tamper]
// edits. Register and Assert fill it from the options, the origin argument and
// the [AuthenticatorConfig], run the Tampers in order, and only then encode the
// client data and the authenticator data and sign them. Every edit is signed,
// so a forged value reaches the relying party's check for that value instead
// of failing at the signature.
//
// A Tamper edits one ceremony and nothing else: the authenticator's key,
// credential ID, remembered user handle and counter are unchanged by it.
type Ceremony struct {
	// Type is the client data type: "webauthn.create" or "webauthn.get".
	Type string

	// Challenge is the client data challenge: the options' challenge,
	// base64url without padding.
	Challenge string

	// Origin is the client data origin: the origin argument.
	Origin string

	// TopOrigin is the client data topOrigin, sent only when non-empty.
	TopOrigin string

	// CrossOrigin is the client data crossOrigin. It is always sent, false by
	// default, as WebAuthn Level 3 §5.8.1.1 serializes it.
	CrossOrigin bool

	// RPID is hashed into the authenticator data: rp.id of the creation
	// options or rpId of the request options, or the origin's host when the
	// options name none.
	RPID string

	// Flags is the authenticator data flags byte: UP (0x01) always, UV (0x04),
	// BE (0x08) and BS (0x10) per the configuration, and AT (0x40) at
	// registration. Register always appends the attested credential data and
	// Assert never does, whatever AT says.
	Flags byte

	// SignCount is the authenticator data counter: the authenticator's counter
	// at registration, the counter plus CounterStep at assertion.
	SignCount uint32

	// CredentialID is sent as id and rawId and, at registration, in the
	// attested credential data.
	CredentialID []byte

	// UserHandle is sent as the assertion's userHandle when non-empty. Assert
	// sets it to the handle Register remembered when the credential is
	// Discoverable, and leaves it empty otherwise. Register sets it to the
	// options' user.id for reference only: a creation response carries no
	// user handle.
	UserHandle []byte

	// ReportedAlgorithm is sent as the registration response's
	// publicKeyAlgorithm; it defaults to the configured algorithm. The client
	// reports that member and no signature covers it, so a relying party must
	// take the algorithm from the attested COSE key: forging it here shows
	// whether it does. Assert ignores it.
	ReportedAlgorithm int

	// OmitCredProps withholds credProps from a registration whose options
	// request it.
	OmitCredProps bool

	// CorruptSignature flips one bit of the assertion signature after signing.
	// Register refuses it: attestation "none" carries no signature.
	CorruptSignature bool

	// RawECDSA encodes an ES256 assertion signature as raw r||s (64 bytes)
	// instead of ASN.1 DER. Register and Ed25519 authenticators refuse it.
	RawECDSA bool
}

// Tamper edits a [Ceremony] before it is encoded and signed. A nil Tamper is
// skipped, so a table test can leave the field unset for its honest case.
type Tamper func(*Ceremony)

// Authenticator is a software WebAuthn authenticator holding one credential.
// It models a client an attacker may control: it signs whatever the Ceremony
// says, takes its flags from the configuration and the Tampers rather than
// from the options, and enforces neither pubKeyCredParams nor
// excludeCredentials at registration nor allowCredentials at assertion, so a
// test can reach every check the relying party makes on its own.
//
// Calls are serialized, and a Tamper runs inside the call, under the
// Authenticator's lock: a Tamper must not call SetSignCount, Register or
// Assert on the Authenticator running it, or the call deadlocks.
type Authenticator struct {
	cfg     AuthenticatorConfig
	alg     int                // the COSE algorithm: -7 or -8
	ecKey   *ecdsa.PrivateKey  // ES256; nil for Ed25519
	edKey   ed25519.PrivateKey // Ed25519; nil for ES256
	coseKey []byte             // the credential public key as a COSE_Key
	spki    []byte             // the same key as DER SubjectPublicKeyInfo
	credID  []byte

	mu      sync.Mutex
	counter uint32
	handle  []byte
}

// NewAuthenticator returns an authenticator with a fresh key pair and a random
// 32-byte credential ID.
func NewAuthenticator(cfg AuthenticatorConfig) (*Authenticator, error) {
	a := &Authenticator{cfg: cfg, counter: cfg.SignCount, credID: make([]byte, 32)}
	if _, err := rand.Read(a.credID); err != nil {
		return nil, fmt.Errorf("authtest: credential ID: %w", err)
	}

	var (
		key any
		pub any
		err error
	)
	switch cfg.Algorithm {
	case 0, int(webauthncose.AlgES256):
		a.alg = int(webauthncose.AlgES256)
		if a.ecKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			return nil, fmt.Errorf("authtest: generate ES256 key: %w", err)
		}
		var point []byte // 0x04 || x || y, each coordinate 32 bytes
		if point, err = a.ecKey.PublicKey.Bytes(); err != nil {
			return nil, fmt.Errorf("authtest: encode ES256 key: %w", err)
		}
		pub = &a.ecKey.PublicKey
		key = webauthncose.EC2PublicKeyData{
			PublicKeyData: webauthncose.PublicKeyData{
				KeyType:   int64(webauthncose.EllipticKey),
				Algorithm: int64(webauthncose.AlgES256),
			},
			Curve:  int64(webauthncose.P256),
			XCoord: point[1:33],
			YCoord: point[33:65],
		}
	case int(webauthncose.AlgEdDSA):
		a.alg = int(webauthncose.AlgEdDSA)
		var edPub ed25519.PublicKey
		if edPub, a.edKey, err = ed25519.GenerateKey(rand.Reader); err != nil {
			return nil, fmt.Errorf("authtest: generate Ed25519 key: %w", err)
		}
		pub = edPub
		key = webauthncose.OKPPublicKeyData{
			PublicKeyData: webauthncose.PublicKeyData{
				KeyType:   int64(webauthncose.OctetKey),
				Algorithm: int64(webauthncose.AlgEdDSA),
			},
			Curve:  int64(webauthncose.Ed25519),
			XCoord: edPub,
		}
	default:
		return nil, fmt.Errorf("authtest: algorithm %d is not supported; use -7 (ES256) or -8 (Ed25519)", cfg.Algorithm)
	}

	if a.coseKey, err = webauthncbor.Marshal(key); err != nil {
		return nil, fmt.Errorf("authtest: encode COSE key: %w", err)
	}
	if a.spki, err = x509.MarshalPKIXPublicKey(pub); err != nil {
		return nil, fmt.Errorf("authtest: encode SubjectPublicKeyInfo: %w", err)
	}
	return a, nil
}

// CredentialID returns a copy of the authenticator's credential ID.
func (a *Authenticator) CredentialID() []byte {
	return bytes.Clone(a.credID)
}

// SetSignCount sets the signature counter. The next assertion signs n plus
// CounterStep, so a value below the relying party's stored counter produces a
// counter regression, the mark of a cloned authenticator.
func (a *Authenticator) SetSignCount(n uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.counter = n
}

// Register answers navigator.credentials.create(). optionsJSON is the
// PublicKeyCredentialCreationOptionsJSON object (the "publicKey" member, not
// the object wrapping it); the result is the browser's
// PublicKeyCredential.toJSON() of the new credential, with attestation "none"
// and the Level 3 members authenticatorData, publicKey (DER
// SubjectPublicKeyInfo) and publicKeyAlgorithm. The authenticator remembers
// user.id as the credential's user handle. The counter does not move.
func (a *Authenticator) Register(optionsJSON []byte, origin string, t ...Tamper) ([]byte, error) {
	var opts creationOptions
	if err := json.Unmarshal(optionsJSON, &opts); err != nil {
		return nil, fmt.Errorf("authtest: decode creation options: %w", err)
	}
	if len(opts.Challenge) == 0 {
		return nil, errNoChallenge
	}
	rpID, err := rpIDFor(opts.RP.ID, origin)
	if err != nil {
		return nil, err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	c := Ceremony{
		Type:              string(protocol.CreateCeremony),
		Challenge:         base64.RawURLEncoding.EncodeToString(opts.Challenge),
		Origin:            origin,
		RPID:              rpID,
		Flags:             a.flags() | byte(protocol.FlagAttestedCredentialData),
		SignCount:         a.counter,
		CredentialID:      bytes.Clone(a.credID),
		UserHandle:        bytes.Clone(opts.User.ID),
		ReportedAlgorithm: a.alg,
	}
	apply(&c, t)
	if c.CorruptSignature || c.RawECDSA {
		return nil, errors.New("authtest: attestation none carries no signature; CorruptSignature and RawECDSA apply to Assert")
	}
	if len(c.CredentialID) > math.MaxUint16 {
		return nil, fmt.Errorf("authtest: credential ID of %d bytes does not fit attested credential data", len(c.CredentialID))
	}

	attested := make([]byte, 0, len(a.cfg.AAGUID)+2+len(c.CredentialID)+len(a.coseKey))
	attested = append(attested, a.cfg.AAGUID[:]...)
	attested = binary.BigEndian.AppendUint16(attested, uint16(len(c.CredentialID)))
	attested = append(attested, c.CredentialID...)
	attested = append(attested, a.coseKey...)

	authData := authenticatorData(&c, attested)
	attestationObject, err := webauthncbor.Marshal(noneAttestation{
		Format:    "none",
		Statement: map[string]any{},
		AuthData:  authData,
	})
	if err != nil {
		return nil, fmt.Errorf("authtest: encode attestation object: %w", err)
	}
	clientDataJSON, err := clientData(&c)
	if err != nil {
		return nil, err
	}

	attachment, transport := a.attachment()
	resp := credentialJSON[attestationResponseJSON]{
		ID:    b64(c.CredentialID),
		RawID: b64(c.CredentialID),
		Type:  string(protocol.PublicKeyCredentialType),
		Response: attestationResponseJSON{
			ClientDataJSON:     b64(clientDataJSON),
			AuthenticatorData:  b64(authData),
			Transports:         []string{transport},
			PublicKey:          b64(a.spki),
			PublicKeyAlgorithm: c.ReportedAlgorithm,
			AttestationObject:  b64(attestationObject),
		},
		AuthenticatorAttachment: attachment,
	}
	if opts.Extensions.CredProps && !c.OmitCredProps {
		resp.ClientExtensionResults.CredProps = &credPropsJSON{RK: a.cfg.Discoverable}
	}
	out, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("authtest: encode registration response: %w", err)
	}

	a.handle = bytes.Clone(opts.User.ID)
	return out, nil
}

// Assert answers navigator.credentials.get(). optionsJSON is the
// PublicKeyCredentialRequestOptionsJSON object (the "publicKey" member); the
// result is the browser's PublicKeyCredential.toJSON() of the assertion. The
// credential is used whether or not allowCredentials lists it, so a foreign
// authenticator reaches the relying party's own credential checks. The counter
// advances by CounterStep when a response is returned; an advance past the
// largest uint32 is refused rather than wrapped.
func (a *Authenticator) Assert(optionsJSON []byte, origin string, t ...Tamper) ([]byte, error) {
	var opts requestOptions
	if err := json.Unmarshal(optionsJSON, &opts); err != nil {
		return nil, fmt.Errorf("authtest: decode request options: %w", err)
	}
	if len(opts.Challenge) == 0 {
		return nil, errNoChallenge
	}
	rpID, err := rpIDFor(opts.RPID, origin)
	if err != nil {
		return nil, err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.cfg.CounterStep > math.MaxUint32-a.counter {
		return nil, fmt.Errorf("authtest: counter %d plus step %d overflows uint32", a.counter, a.cfg.CounterStep)
	}
	next := a.counter + a.cfg.CounterStep
	c := Ceremony{
		Type:              string(protocol.AssertCeremony),
		Challenge:         base64.RawURLEncoding.EncodeToString(opts.Challenge),
		Origin:            origin,
		RPID:              rpID,
		Flags:             a.flags(),
		SignCount:         next,
		CredentialID:      bytes.Clone(a.credID),
		ReportedAlgorithm: a.alg,
	}
	if a.cfg.Discoverable {
		c.UserHandle = bytes.Clone(a.handle)
	}
	apply(&c, t)
	if c.RawECDSA && a.ecKey == nil {
		return nil, errors.New("authtest: RawECDSA applies to ES256 only")
	}

	authData := authenticatorData(&c, nil)
	clientDataJSON, err := clientData(&c)
	if err != nil {
		return nil, err
	}
	clientDataHash := sha256.Sum256(clientDataJSON)
	signed := make([]byte, 0, len(authData)+len(clientDataHash))
	signed = append(signed, authData...)
	signed = append(signed, clientDataHash[:]...)
	sig, err := a.sign(signed, c.RawECDSA)
	if err != nil {
		return nil, err
	}
	if c.CorruptSignature {
		sig[len(sig)-1] ^= 0x01
	}

	attachment, _ := a.attachment()
	resp := credentialJSON[assertionResponseJSON]{
		ID:    b64(c.CredentialID),
		RawID: b64(c.CredentialID),
		Type:  string(protocol.PublicKeyCredentialType),
		Response: assertionResponseJSON{
			ClientDataJSON:    b64(clientDataJSON),
			AuthenticatorData: b64(authData),
			Signature:         b64(sig),
			UserHandle:        b64(c.UserHandle),
		},
		AuthenticatorAttachment: attachment,
	}
	out, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("authtest: encode assertion response: %w", err)
	}

	a.counter = next
	return out, nil
}

var errNoChallenge = errors.New("authtest: options carry no challenge; pass the publicKey object itself")

// flags returns the configured flags byte, without AT.
func (a *Authenticator) flags() byte {
	f := byte(protocol.FlagUserPresent)
	if a.cfg.UserVerified {
		f |= byte(protocol.FlagUserVerified)
	}
	if a.cfg.BackupEligible {
		f |= byte(protocol.FlagBackupEligible)
	}
	if a.cfg.BackupState {
		f |= byte(protocol.FlagBackupState)
	}
	return f
}

// attachment returns the self-reported authenticatorAttachment and transport:
// a backup-eligible credential presents as a platform passkey ("internal"),
// any other as a roaming security key ("usb"). Both are hints a relying party
// must never treat as evidence.
func (a *Authenticator) attachment() (attachment, transport string) {
	if a.cfg.BackupEligible {
		return string(protocol.Platform), string(protocol.Internal)
	}
	return string(protocol.CrossPlatform), string(protocol.USB)
}

// sign signs data as WebAuthn requires: ES256 over its SHA-256 digest (ASN.1
// DER, or raw r||s when raw is set), Ed25519 over the data itself.
func (a *Authenticator) sign(data []byte, raw bool) ([]byte, error) {
	if a.ecKey == nil {
		return ed25519.Sign(a.edKey, data), nil
	}
	digest := sha256.Sum256(data)
	if !raw {
		sig, err := ecdsa.SignASN1(rand.Reader, a.ecKey, digest[:])
		if err != nil {
			return nil, fmt.Errorf("authtest: sign: %w", err)
		}
		return sig, nil
	}
	r, s, err := ecdsa.Sign(rand.Reader, a.ecKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("authtest: sign: %w", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig, nil
}

func apply(c *Ceremony, tampers []Tamper) {
	for _, t := range tampers {
		if t != nil {
			t(c)
		}
	}
}

// rpIDFor returns the RP ID the options name or, when they name none, the
// origin's host, as a browser does.
func rpIDFor(rpID, origin string) (string, error) {
	if rpID != "" {
		return rpID, nil
	}
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("authtest: options name no RP ID and origin %q has no host", origin)
	}
	return u.Hostname(), nil
}

// authenticatorData encodes rpIdHash | flags | signCount | attested.
func authenticatorData(c *Ceremony, attested []byte) []byte {
	rpIDHash := sha256.Sum256([]byte(c.RPID))
	data := make([]byte, 0, len(rpIDHash)+1+4+len(attested))
	data = append(data, rpIDHash[:]...)
	data = append(data, c.Flags)
	data = binary.BigEndian.AppendUint32(data, c.SignCount)
	return append(data, attested...)
}

// clientData serializes the client data as browsers do (WebAuthn Level 3
// §5.8.1.1): members in collectedClientData order, no HTML escaping, and no
// trailing newline, which would otherwise end up in the signed bytes.
func clientData(c *Ceremony) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(collectedClientData{
		Type:        c.Type,
		Challenge:   c.Challenge,
		Origin:      c.Origin,
		CrossOrigin: c.CrossOrigin,
		TopOrigin:   c.TopOrigin,
	}); err != nil {
		return nil, fmt.Errorf("authtest: encode client data: %w", err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// b64 is the unpadded base64url the JSON forms of WebAuthn use.
func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// creationOptions is the part of PublicKeyCredentialCreationOptionsJSON the
// authenticator reads.
type creationOptions struct {
	RP         rpEntityJSON              `json:"rp"`
	User       userEntityJSON            `json:"user"`
	Challenge  protocol.URLEncodedBase64 `json:"challenge"`
	Extensions creationExtensionsJSON    `json:"extensions"`
}

type rpEntityJSON struct {
	ID string `json:"id"`
}

type userEntityJSON struct {
	ID protocol.URLEncodedBase64 `json:"id"`
}

type creationExtensionsJSON struct {
	CredProps bool `json:"credProps"`
}

// requestOptions is the part of PublicKeyCredentialRequestOptionsJSON the
// authenticator reads.
type requestOptions struct {
	Challenge protocol.URLEncodedBase64 `json:"challenge"`
	RPID      string                    `json:"rpId"`
}

// collectedClientData is CollectedClientData in the member order browsers send.
type collectedClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
	TopOrigin   string `json:"topOrigin,omitempty"`
}

// noneAttestation is an attestation object in the "none" format.
type noneAttestation struct {
	Format    string         `cbor:"fmt"`
	Statement map[string]any `cbor:"attStmt"`
	AuthData  []byte         `cbor:"authData"`
}

// credentialJSON is PublicKeyCredential.toJSON().
type credentialJSON[R any] struct {
	ID                      string                     `json:"id"`
	RawID                   string                     `json:"rawId"`
	Type                    string                     `json:"type"`
	Response                R                          `json:"response"`
	ClientExtensionResults  clientExtensionResultsJSON `json:"clientExtensionResults"`
	AuthenticatorAttachment string                     `json:"authenticatorAttachment,omitempty"`
}

// attestationResponseJSON is AuthenticatorAttestationResponseJSON, in the
// member order of the IDL.
type attestationResponseJSON struct {
	ClientDataJSON     string   `json:"clientDataJSON"`
	AuthenticatorData  string   `json:"authenticatorData"`
	Transports         []string `json:"transports"`
	PublicKey          string   `json:"publicKey"`
	PublicKeyAlgorithm int      `json:"publicKeyAlgorithm"`
	AttestationObject  string   `json:"attestationObject"`
}

type assertionResponseJSON struct {
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle,omitempty"`
}

type clientExtensionResultsJSON struct {
	CredProps *credPropsJSON `json:"credProps,omitempty"`
}

type credPropsJSON struct {
	RK bool `json:"rk"`
}
