package jwt

// Adversarial suite for auth/jwt.
//
// Every test here is named for the attack it defends against and is written so
// that it fails if the corresponding hardening is removed. The register these
// findings come from is docs/security-hardening.md; section 6 of that document
// is the plan this file implements for the JWT primitive.
//
// The forged tokens are built segment by segment rather than through the
// library's own minting path wherever the attack depends on a shape a
// well-behaved minter never produces.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/meysam81/go-auth/storage"
)

const (
	advUserID   = "user-victim"
	advAttacker = "user-attacker"
	advIssuer   = "https://idp.example.com"
	advAudience = "https://api.example.com"
)

// advSecret returns n bytes of key material from crypto/rand. A hardcoded
// secret would make several of these tests pass for the wrong reason: a forged
// token that happens to collide with a fixture is not evidence of anything.
func advSecret(t *testing.T, n int) []byte {
	t.Helper()

	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return b
}

// advManager builds a manager, supplying an in-memory user store when the test
// does not care which one is used.
func advManager(t *testing.T, cfg Config) *TokenManager {
	t.Helper()

	if cfg.UserStore == nil {
		cfg.UserStore = storage.NewInMemoryUserStore()
	}

	tm, err := NewTokenManager(cfg)
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	if tm == nil {
		t.Fatal("NewTokenManager returned a nil manager and a nil error")
	}
	return tm
}

// advStoredUser creates a user in the store so that a rejection on the refresh
// path can only come from the token, never from a missing row.
func advStoredUser(ctx context.Context, t *testing.T, store storage.UserStore, id string) *storage.User {
	t.Helper()

	user := &storage.User{ID: id, Email: id + "@example.com"}
	if err := store.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser(%s): %v", id, err)
	}
	return user
}

// advSign signs an arbitrary claim set. The signature is genuine, so a
// rejection can only come from the claim or the pinned algorithm -- which is
// what makes these cases hostile rather than merely malformed.
func advSign(t *testing.T, method jwt.SigningMethod, key any, claims jwt.MapClaims) string {
	t.Helper()

	signed, err := jwt.NewWithClaims(method, claims).SignedString(key)
	if err != nil {
		t.Fatalf("SignedString(%s): %v", method.Alg(), err)
	}
	return signed
}

// advForge assembles a token from raw segments without the library's
// cooperation, which is the only way to express a header golang-jwt refuses to
// emit -- an unsecured token, a non-string alg, a hostile kid.
func advForge(t *testing.T, header, payload map[string]any, signature string) string {
	t.Helper()

	return advSegment(t, header) + "." + advSegment(t, payload) + "." + signature
}

func advSegment(t *testing.T, v map[string]any) string {
	t.Helper()

	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

// advClaims is a claim set that validates cleanly, so that a test mutating one
// field isolates that field as the reason for the verdict.
func advClaims(now time.Time, mutate func(jwt.MapClaims)) jwt.MapClaims {
	claims := jwt.MapClaims{
		"uid":  advUserID,
		"sub":  advUserID,
		"type": string(AccessToken),
		"iat":  now.Unix(),
		"nbf":  now.Unix(),
		"exp":  now.Add(time.Hour).Unix(),
	}
	if mutate != nil {
		mutate(claims)
	}
	return claims
}

func advPayload(now time.Time, mutate func(map[string]any)) map[string]any {
	payload := map[string]any{
		"uid":  advUserID,
		"sub":  advUserID,
		"type": string(AccessToken),
		"iat":  now.Unix(),
		"nbf":  now.Unix(),
		"exp":  now.Add(time.Hour).Unix(),
	}
	if mutate != nil {
		mutate(payload)
	}
	return payload
}

// advSurface is one externally reachable entry point that turns a token into
// authority: a nil error means the surface accepted the credential.
type advSurface struct {
	name string
	call func(ctx context.Context, t *testing.T, tm *TokenManager, token string) error
}

// advAuthSurfaces enumerates every entry point that grants something on
// success. A forgery has to be refused by all of them, not by the one the test
// author happened to think of.
func advAuthSurfaces() []advSurface {
	return []advSurface{
		{
			name: "ValidateToken",
			call: func(ctx context.Context, t *testing.T, tm *TokenManager, token string) error {
				claims, err := tm.ValidateToken(ctx, token)
				if err != nil && claims != nil {
					t.Errorf("ValidateToken returned claims %+v alongside error %v", claims, err)
				}
				return err
			},
		},
		{
			name: "ValidateAccessToken",
			call: func(ctx context.Context, t *testing.T, tm *TokenManager, token string) error {
				claims, err := tm.ValidateAccessToken(ctx, token)
				if err != nil && claims != nil {
					t.Errorf("ValidateAccessToken returned claims %+v alongside error %v", claims, err)
				}
				return err
			},
		},
		{
			name: "ValidateRefreshToken",
			call: func(ctx context.Context, t *testing.T, tm *TokenManager, token string) error {
				claims, err := tm.ValidateRefreshToken(ctx, token)
				if err != nil && claims != nil {
					t.Errorf("ValidateRefreshToken returned claims %+v alongside error %v", claims, err)
				}
				return err
			},
		},
		{
			name: "RefreshAccessToken",
			call: func(ctx context.Context, t *testing.T, tm *TokenManager, token string) error {
				pair, err := tm.RefreshAccessToken(ctx, token)
				if err != nil && pair != nil {
					t.Errorf("RefreshAccessToken returned a token pair alongside error %v", err)
				}
				return err
			},
		},
		{
			name: "RevokeRefreshToken",
			call: func(ctx context.Context, t *testing.T, tm *TokenManager, token string) error {
				return tm.RevokeRefreshToken(ctx, token)
			},
		},
	}
}

// advRejectOnEverySurface asserts that no entry point accepts the token.
func advRejectOnEverySurface(ctx context.Context, t *testing.T, tm *TokenManager, token string) {
	t.Helper()

	for _, surface := range advAuthSurfaces() {
		if err := surface.call(ctx, t, tm, token); err == nil {
			t.Errorf("%s ACCEPTED the forged token", surface.name)
		}
	}
}

// advTokenID reads the jti out of a token without verifying it, the way an
// attacker holding somebody else's token reads it.
func advTokenID(t *testing.T, token string) string {
	t.Helper()

	claims, err := ParseUnverified(token)
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	if claims.TokenID == "" {
		t.Fatal("Expected a jti on a refresh token")
	}
	return claims.TokenID
}

// advBrokenSigner is a crypto.Signer whose public half is not what the
// configured signing method requires. A library that type-asserts without
// checking panics on it; the constructor must report a configuration error
// instead.
type advBrokenSigner struct {
	public crypto.PublicKey
}

func (s advBrokenSigner) Public() crypto.PublicKey { return s.public }

func (advBrokenSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("advBrokenSigner never signs")
}

// TestJWT_AlgNoneForgeryRejected covers the unsecured-JWT forgery: RFC 7519
// section 6 defines a token whose alg is "none" and whose signature is the
// empty string, and RFC 8725 section 3.1 requires a verifier to decide the
// algorithm from its own configuration rather than from the attacker-supplied
// header. This is the first half of the 2015 "critical vulnerabilities in JSON
// Web Token libraries" disclosure that golang-jwt's own parser documentation
// links to.
//
// The defense has two halves and both are asserted here: the manager must never
// be configurable to MINT an unsecured token (NewTokenManager rejects
// SigningMethodNone, which it did not before this release), and no entry point
// may ACCEPT one.
func TestJWT_AlgNoneForgeryRejected(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	secret := advSecret(t, 32)
	userStore := storage.NewInMemoryUserStore()
	advStoredUser(ctx, t, userStore, advUserID)

	tm := advManager(t, Config{
		UserStore:  userStore,
		TokenStore: storage.NewInMemoryTokenStore(),
		SigningKey: secret,
	})

	now := time.Now()
	payload := advPayload(now, func(p map[string]any) {
		p["jti"] = "forged-jti"
	})

	tests := []struct {
		name   string
		header map[string]any
		sig    string
	}{
		{"alg none with an empty signature", map[string]any{"alg": "none", "typ": "JWT"}, ""},
		{"alg none carrying a junk signature", map[string]any{"alg": "none", "typ": "JWT"}, "aGVsbG8"},
		{"alg None, title case", map[string]any{"alg": "None", "typ": "JWT"}, ""},
		{"alg NONE, upper case", map[string]any{"alg": "NONE", "typ": "JWT"}, ""},
		{"alg nOnE, mixed case", map[string]any{"alg": "nOnE", "typ": "JWT"}, ""},
		{"alg none with a trailing space", map[string]any{"alg": "none ", "typ": "JWT"}, ""},
		{"alg none with a NUL byte", map[string]any{"alg": "none\x00", "typ": "JWT"}, ""},
		{"alg none plus a kid, hoping the kid selects the key", map[string]any{"alg": "none", "kid": "../../dev/null"}, ""},
		{"alg absent entirely", map[string]any{"typ": "JWT"}, ""},
		{"alg as a JSON number", map[string]any{"alg": 0}, ""},
		{"alg as an array", map[string]any{"alg": []string{"none", "HS256"}}, ""},
		{"alg as null", map[string]any{"alg": nil}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			advRejectOnEverySurface(ctx, t, tm, advForge(t, tc.header, payload, tc.sig))
		})
	}

	t.Run("the two-segment form of an unsecured token", func(t *testing.T) {
		t.Parallel()

		forged := advForge(t, map[string]any{"alg": "none"}, payload, "")
		advRejectOnEverySurface(ctx, t, tm, strings.TrimSuffix(forged, "."))
	})

	// A manager that can mint an unsecured token is a manager whose tokens are
	// forgeable by anyone. Before this release the constructor accepted the
	// configuration and failed at the first signature.
	t.Run("a manager cannot be configured to mint unsecured tokens", func(t *testing.T) {
		t.Parallel()

		tm, err := NewTokenManager(Config{
			UserStore:     storage.NewInMemoryUserStore(),
			SigningKey:    advSecret(t, 32),
			SigningMethod: jwt.SigningMethodNone,
		})
		if err == nil {
			t.Fatal("NewTokenManager accepted the none signing method")
		}
		if !errors.Is(err, ErrInvalidKeyConfig) {
			t.Fatalf("Expected ErrInvalidKeyConfig, got %v", err)
		}
		if tm != nil {
			t.Fatal("Expected a nil manager alongside the error")
		}
	})
}

// TestJWT_AlgorithmConfusionRSAPublicKeyAsHMACSecret covers the second half of
// the same 2015 disclosure and RFC 8725 section 3.1: against a verifier that
// takes the algorithm from the token, an attacker signs HS256 using the RSA
// verification key -- which is public by construction -- and the verifier
// happily HMACs with it.
//
// F-04 is the precondition: until asymmetric signing worked at all, this
// deployment shape did not exist. The test therefore also proves the genuine
// RS256/ES256 round trip, so it fails if asymmetric signing regresses to the
// state where the constructor accepts the configuration and the first mint
// fails.
func TestJWT_AlgorithmConfusionRSAPublicKeyAsHMACSecret(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	userStore := storage.NewInMemoryUserStore()
	user := advStoredUser(ctx, t, userStore, advUserID)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}

	pkix, err := x509.MarshalPKIXPublicKey(rsaKey.Public())
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pkixPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix})
	pkcs1 := x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)
	pkcs1PEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pkcs1})

	ecPKIX, err := x509.MarshalPKIXPublicKey(ecKey.Public())
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey(ec): %v", err)
	}

	// Every serialization an attacker might guess the deployment publishes.
	// Guessing right is the whole attack, so the test guesses all of them.
	forgedKeys := map[string][]byte{
		"PKIX DER":                            pkix,
		"PKIX PEM":                            pkixPEM,
		"PKIX PEM without a trailing newline": []byte(strings.TrimRight(string(pkixPEM), "\n")),
		"PKCS#1 DER":                          pkcs1,
		"PKCS#1 PEM":                          pkcs1PEM,
		"the raw modulus":                     rsaKey.N.Bytes(),
		"base64 of the PKIX DER":              []byte(base64.StdEncoding.EncodeToString(pkix)),
		"the P-256 public point":              ecPKIX,
	}

	asymmetric := []struct {
		name   string
		method jwt.SigningMethod
		key    crypto.Signer
	}{
		{"RS256", jwt.SigningMethodRS256, rsaKey},
		{"PS256", jwt.SigningMethodPS256, rsaKey},
		{"ES256", jwt.SigningMethodES256, ecKey},
	}
	for _, family := range asymmetric {
		t.Run(family.name, func(t *testing.T) {
			t.Parallel()

			tm := advManager(t, Config{
				UserStore:     userStore,
				TokenStore:    storage.NewInMemoryTokenStore(),
				PrivateKey:    family.key,
				SigningMethod: family.method,
				Issuer:        advIssuer,
			})

			// F-04: the honest path must work, or the confusion test below is
			// asserting nothing about a deployment that can exist.
			pair, err := tm.GenerateTokenPair(ctx, user)
			if err != nil {
				t.Fatalf("GenerateTokenPair: %v", err)
			}
			if _, err := tm.ValidateAccessToken(ctx, pair.AccessToken); err != nil {
				t.Fatalf("A genuine %s access token must validate: %v", family.method.Alg(), err)
			}

			now := time.Now()
			claims := advClaims(now, func(c jwt.MapClaims) {
				c["uid"] = advAttacker
				c["iss"] = advIssuer
				c["jti"] = advTokenID(t, pair.RefreshToken)
			})

			for name, key := range forgedKeys {
				t.Run("HS256 signed with "+name, func(t *testing.T) {
					t.Parallel()

					advRejectOnEverySurface(ctx, t, tm, advSign(t, jwt.SigningMethodHS256, key, claims))
				})
				t.Run("HS512 signed with "+name, func(t *testing.T) {
					t.Parallel()

					advRejectOnEverySurface(ctx, t, tm, advSign(t, jwt.SigningMethodHS512, key, claims))
				})
			}

			// The mirror image: a symmetric deployment must not accept a token
			// that claims an asymmetric algorithm it never configured.
			t.Run("the reverse substitution against an HMAC manager", func(t *testing.T) {
				t.Parallel()

				hmacManager := advManager(t, Config{
					UserStore:  userStore,
					TokenStore: storage.NewInMemoryTokenStore(),
					SigningKey: advSecret(t, 32),
					Issuer:     advIssuer,
				})
				advRejectOnEverySurface(ctx, t, hmacManager, advSign(t, family.method, family.key, claims))
			})
		})
	}
}

// TestJWT_SigningMethodSubstitutionOnRevokePath covers F-03's revocation half.
// RevokeRefreshToken used to parse with a key function that inspected nothing:
// it returned the HMAC secret for whatever algorithm the token named. Every
// member of the HMAC family therefore verified against it, so a component
// holding the shared secret -- the deployment shape F-03 is about -- could name
// any jti and have it revoked.
//
// The security property is not the returned error. It is that the victim's
// refresh token is still usable afterwards, which is what these subtests
// assert, and what fails when the pin is removed.
func TestJWT_SigningMethodSubstitutionOnRevokePath(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	secret := advSecret(t, 32)

	newVictim := func(t *testing.T) (*TokenManager, *TokenPair) {
		t.Helper()

		userStore := storage.NewInMemoryUserStore()
		user := advStoredUser(ctx, t, userStore, advUserID)
		tm := advManager(t, Config{
			UserStore:  userStore,
			TokenStore: storage.NewInMemoryTokenStore(),
			SigningKey: secret,
			Issuer:     advIssuer,
			Audience:   []string{advAudience},
		})
		pair, err := tm.GenerateTokenPair(ctx, user)
		if err != nil {
			t.Fatalf("GenerateTokenPair: %v", err)
		}
		return tm, pair
	}

	tests := []struct {
		name   string
		method jwt.SigningMethod
		key    any
		mutate func(jwt.MapClaims)
	}{
		{
			name:   "HS512 substituted for the pinned HS256",
			method: jwt.SigningMethodHS512,
			key:    secret,
		},
		{
			name:   "HS384 substituted for the pinned HS256",
			method: jwt.SigningMethodHS384,
			key:    secret,
		},
		{
			name:   "an unsecured token naming the victim's jti",
			method: jwt.SigningMethodNone,
			key:    jwt.UnsafeAllowNoneSignatureType,
		},
		{
			name:   "an access token carrying a refresh token's jti",
			method: jwt.SigningMethodHS256,
			key:    secret,
			mutate: func(c jwt.MapClaims) { c["type"] = string(AccessToken) },
		},
		{
			name:   "a token with no exp at all",
			method: jwt.SigningMethodHS256,
			key:    secret,
			mutate: func(c jwt.MapClaims) { delete(c, "exp") },
		},
		{
			name:   "a token from a service sharing the secret under another issuer",
			method: jwt.SigningMethodHS256,
			key:    secret,
			mutate: func(c jwt.MapClaims) { c["iss"] = "https://batch.internal" },
		},
		{
			name:   "a token minted for another audience",
			method: jwt.SigningMethodHS256,
			key:    secret,
			mutate: func(c jwt.MapClaims) { c["aud"] = "https://batch.internal" },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tm, pair := newVictim(t)
			now := time.Now()
			claims := advClaims(now, func(c jwt.MapClaims) {
				c["type"] = string(RefreshToken)
				c["iss"] = advIssuer
				c["aud"] = advAudience
				c["jti"] = advTokenID(t, pair.RefreshToken)
				if tc.mutate != nil {
					tc.mutate(c)
				}
			})

			if err := tm.RevokeRefreshToken(ctx, advSign(t, tc.method, tc.key, claims)); err == nil {
				t.Error("RevokeRefreshToken ACCEPTED the forged token")
			}

			// The victim's credential must be untouched.
			if _, err := tm.ValidateRefreshToken(ctx, pair.RefreshToken); err != nil {
				t.Fatalf("The victim's refresh token was revoked by the forgery: %v", err)
			}
			if _, err := tm.RefreshAccessToken(ctx, pair.RefreshToken); err != nil {
				t.Fatalf("The victim can no longer refresh: %v", err)
			}
		})
	}
}

// TestJWT_RefreshTokenPresentedAsBearerRejected covers F-02 (CWE-863), the one
// finding in the register with an executed proof. RFC 8725 section 2.8 names
// the class "cross-JWT confusion" and section 3.12 requires mutually exclusive
// validation rules for tokens minted for different purposes.
//
// ValidateToken -- the function the bearer middleware calls -- never inspected
// the type claim, so a refresh token authorized every route: seven days of
// validity in place of fifteen minutes, from the credential most likely to be
// sitting in client storage.
//
// The store-less manager is the sharpest form of the proof: with no token store
// there is no jti lookup to fail, so nothing but the type claim stands between
// the refresh token and the protected route.
func TestJWT_RefreshTokenPresentedAsBearerRejected(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	secret := advSecret(t, 32)

	managers := []struct {
		name       string
		tokenStore storage.TokenStore
	}{
		{"with a token store", storage.NewInMemoryTokenStore()},
		{"without a token store, where only the type claim can refuse it", nil},
	}
	for _, mc := range managers {
		t.Run(mc.name, func(t *testing.T) {
			t.Parallel()

			userStore := storage.NewInMemoryUserStore()
			user := advStoredUser(ctx, t, userStore, advUserID)
			tm := advManager(t, Config{
				UserStore:  userStore,
				TokenStore: mc.tokenStore,
				SigningKey: secret,
				Issuer:     advIssuer,
				Audience:   []string{advAudience},
			})

			pair, err := tm.GenerateTokenPair(ctx, user)
			if err != nil {
				t.Fatalf("GenerateTokenPair: %v", err)
			}

			bearer := []struct {
				name     string
				validate func(context.Context, string) (*Claims, error)
			}{
				{"ValidateToken", tm.ValidateToken},
				{"ValidateAccessToken", tm.ValidateAccessToken},
			}
			for _, entry := range bearer {
				claims, err := entry.validate(ctx, pair.RefreshToken)
				if err == nil {
					t.Errorf("%s ACCEPTED a refresh token as a bearer credential", entry.name)
				}
				if claims != nil {
					t.Errorf("%s returned claims %+v for a refresh token", entry.name, claims)
				}
				if !errors.Is(err, ErrUnexpectedTokenType) {
					t.Errorf("%s: expected ErrUnexpectedTokenType, got %v", entry.name, err)
				}
				// v1.1 callers test for ErrInvalidToken; the new sentinel wraps
				// it so their check keeps refusing the token.
				if !errors.Is(err, ErrInvalidToken) {
					t.Errorf("%s: expected the error to remain an ErrInvalidToken, got %v", entry.name, err)
				}
			}

			// The converse: an access token must not reach the refresh or
			// revoke path either, or a fifteen-minute credential becomes a
			// lever on the seven-day one.
			if _, err := tm.ValidateRefreshToken(ctx, pair.AccessToken); !errors.Is(err, ErrUnexpectedTokenType) {
				t.Errorf("ValidateRefreshToken: expected ErrUnexpectedTokenType for an access token, got %v", err)
			}
			if _, err := tm.RefreshAccessToken(ctx, pair.AccessToken); !errors.Is(err, ErrUnexpectedTokenType) {
				t.Errorf("RefreshAccessToken: expected ErrUnexpectedTokenType for an access token, got %v", err)
			}

			// Each credential still works in the role it was minted for.
			if _, err := tm.ValidateAccessToken(ctx, pair.AccessToken); err != nil {
				t.Fatalf("A genuine access token must validate: %v", err)
			}
			if _, err := tm.ValidateRefreshToken(ctx, pair.RefreshToken); err != nil {
				t.Fatalf("A genuine refresh token must validate on the refresh path: %v", err)
			}
		})
	}
}

// TestJWT_TokenTypeClaimConfusionRejected is the type-confusion half of F-02:
// the type claim is the only thing separating two credentials with very
// different blast radii, so it is compared as an exact string and a token that
// omits it, mangles its case, pads it, or replaces it with a non-string is not
// a token of that type.
//
// Every token here carries a genuine signature under the manager's own secret,
// so the verdict can only come from the type claim.
func TestJWT_TokenTypeClaimConfusionRejected(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	secret := advSecret(t, 32)
	userStore := storage.NewInMemoryUserStore()
	advStoredUser(ctx, t, userStore, advUserID)

	tm := advManager(t, Config{
		UserStore:  userStore,
		TokenStore: storage.NewInMemoryTokenStore(),
		SigningKey: secret,
		Issuer:     advIssuer,
	})

	tests := []struct {
		name  string
		value any
		omit  bool
	}{
		{name: "no type claim at all", omit: true},
		{name: "an empty type", value: ""},
		{name: "Access, title case", value: "Access"},
		{name: "ACCESS, upper case", value: "ACCESS"},
		{name: "access with a trailing space", value: "access "},
		{name: "access with a leading space", value: " access"},
		{name: "access with a NUL byte", value: "access\x00"},
		{name: "access with a trailing newline", value: "access\n"},
		{name: "a type claim that is a number", value: 1},
		{name: "a type claim that is a boolean", value: true},
		{name: "a type claim that is an array", value: []string{"access", "refresh"}},
		{name: "a type claim that is an object", value: map[string]any{"access": true}},
		{name: "a type claim that is null", value: nil},
		{name: "an unknown type", value: "session"},
		{name: "the refresh type on the access path", value: string(RefreshToken)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			now := time.Now()
			claims := advClaims(now, func(c jwt.MapClaims) {
				c["iss"] = advIssuer
				if tc.omit {
					delete(c, "type")
					return
				}
				c["type"] = tc.value
			})

			token := advSign(t, jwt.SigningMethodHS256, secret, claims)
			if claims, err := tm.ValidateAccessToken(ctx, token); err == nil {
				t.Fatalf("ValidateAccessToken ACCEPTED %s: %+v", tc.name, claims)
			}
		})
	}
}

// TestJWT_CrossIssuerReplayRejected covers the iss half of F-03 (CWE-347).
// RFC 7519 section 4.1.1 makes iss the claim that names the minting authority,
// and RFC 8725 section 3.8 requires the verifier to check it. Until this
// release iss was written at mint time and never read, so two services rotating
// one secret through their environment -- the normal shape of a shared-secret
// deployment -- accepted each other's tokens.
//
// The comparison must be exact: a substring or prefix match would let
// idp.example.com.evil.test past.
func TestJWT_CrossIssuerReplayRejected(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	shared := advSecret(t, 32)
	userStore := storage.NewInMemoryUserStore()
	advStoredUser(ctx, t, userStore, advUserID)

	tm := advManager(t, Config{
		UserStore:  userStore,
		TokenStore: storage.NewInMemoryTokenStore(),
		SigningKey: shared,
		Issuer:     advIssuer,
	})

	tests := []struct {
		name string
		iss  any
		omit bool
		want bool // want acceptance
	}{
		{name: "our own issuer", iss: advIssuer, want: true},
		{name: "a sibling service sharing the secret", iss: "https://batch.example.com"},
		{name: "no issuer at all", omit: true},
		{name: "an empty issuer", iss: ""},
		{name: "our issuer as a prefix of a hostile one", iss: advIssuer + ".evil.test"},
		{name: "a hostile issuer ending in ours", iss: "https://evil.test/" + advIssuer},
		{name: "our issuer with a trailing slash", iss: advIssuer + "/"},
		{name: "our issuer in a different case", iss: strings.ToUpper(advIssuer)},
		{name: "our issuer with a trailing NUL", iss: advIssuer + "\x00"},
		{name: "an issuer that is a number", iss: 42},
		{name: "an issuer that is an array", iss: []string{advIssuer}},
		{name: "an issuer that is null", iss: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			now := time.Now()
			claims := advClaims(now, func(c jwt.MapClaims) {
				if tc.omit {
					delete(c, "iss")
					return
				}
				c["iss"] = tc.iss
			})

			_, err := tm.ValidateAccessToken(ctx, advSign(t, jwt.SigningMethodHS256, shared, claims))
			switch {
			case tc.want && err != nil:
				t.Fatalf("Expected acceptance, got %v", err)
			case !tc.want && err == nil:
				t.Fatal("ACCEPTED a token from a foreign issuer")
			}
		})
	}
}

// TestJWT_AudienceConfusionAndCrossAudienceReplayRejected covers the aud half
// of F-03. RFC 7519 section 4.1.3 lets aud be either a case-sensitive string or
// an array of them, and that duality is the bug class recorded as
// CVE-2020-26160 against dgrijalva/jwt-go, where a verifier that assumed one
// shape silently skipped the check when handed the other.
//
// Both shapes must be understood, both must be enforced, and a shape that is
// neither must be refused rather than treated as an absent claim.
func TestJWT_AudienceConfusionAndCrossAudienceReplayRejected(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	shared := advSecret(t, 32)
	userStore := storage.NewInMemoryUserStore()
	advStoredUser(ctx, t, userStore, advUserID)

	tm := advManager(t, Config{
		UserStore:  userStore,
		TokenStore: storage.NewInMemoryTokenStore(),
		SigningKey: shared,
		Issuer:     advIssuer,
		Audience:   []string{advAudience},
	})

	tests := []struct {
		name string
		aud  any
		omit bool
		want bool // want acceptance
	}{
		{name: "aud as a bare string naming us", aud: advAudience, want: true},
		{name: "aud as a single-element array naming us", aud: []string{advAudience}, want: true},
		{name: "aud as an array naming us among others", aud: []string{"https://jobs.example.com", advAudience}, want: true},
		{name: "aud missing entirely", omit: true},
		{name: "aud as null", aud: nil},
		{name: "aud as an empty array", aud: []string{}},
		{name: "aud as an array of one empty string", aud: []string{""}},
		{name: "aud as an empty string", aud: ""},
		{name: "aud as a bare string naming another service", aud: "https://jobs.example.com"},
		{name: "aud as an array naming only other services", aud: []string{"https://jobs.example.com", "https://batch.example.com"}},
		{name: "our audience as a prefix of a hostile one", aud: advAudience + ".evil.test"},
		{name: "our audience in a different case", aud: strings.ToUpper(advAudience)},
		{name: "aud as a number", aud: 42},
		{name: "aud as a boolean", aud: true},
		{name: "aud as an object", aud: map[string]any{"aud": advAudience}},
		{name: "aud as an array mixing our audience with a non-string", aud: []any{advAudience, 42}},
		{name: "aud as a nested array", aud: []any{[]string{advAudience}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			now := time.Now()
			claims := advClaims(now, func(c jwt.MapClaims) {
				c["iss"] = advIssuer
				if tc.omit {
					return
				}
				c["aud"] = tc.aud
			})

			_, err := tm.ValidateAccessToken(ctx, advSign(t, jwt.SigningMethodHS256, shared, claims))
			switch {
			case tc.want && err != nil:
				t.Fatalf("Expected acceptance, got %v", err)
			case !tc.want && err == nil:
				t.Fatal("ACCEPTED a token minted for another audience")
			}
		})
	}
}

// TestJWT_ExpiryNotBeforeAndClockSkewBoundaries walks the temporal claims of
// RFC 7519 sections 4.1.4 to 4.1.6 across their boundaries.
//
// The finding this pins is the missing-exp case: exp is OPTIONAL in RFC 7519,
// so a parser left on its defaults accepts a token that carries none, and a
// bearer credential with no expiry is a permanent one. The manager now requires
// it.
//
// The rest of the table pins the boundary itself. golang-jwt accepts a token
// while now is strictly before exp, so a token whose exp equals the current
// second is already expired, and no leeway is configured, so an expired token
// does not become valid again by being only one second late.
//
// One leniency is recorded rather than asserted away: RFC 7519 section 2
// defines a NumericDate as a JSON number, but encoding/json will decode a
// QUOTED number into a json.Number, so "exp": "1767225600" parses. The quoted
// form is still enforced as a time -- which is what the table checks -- so the
// leniency costs nothing here beyond a second wire encoding for one token.
func TestJWT_ExpiryNotBeforeAndClockSkewBoundaries(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	secret := advSecret(t, 32)
	userStore := storage.NewInMemoryUserStore()
	advStoredUser(ctx, t, userStore, advUserID)

	tm := advManager(t, Config{
		UserStore:  userStore,
		TokenStore: storage.NewInMemoryTokenStore(),
		SigningKey: secret,
	})

	tests := []struct {
		name   string
		mutate func(jwt.MapClaims, time.Time)
		want   bool // want acceptance
	}{
		{
			name:   "a token with no exp claim is not a session that never ends",
			mutate: func(c jwt.MapClaims, _ time.Time) { delete(c, "exp") },
		},
		{
			name:   "a null exp is not an absent exp",
			mutate: func(c jwt.MapClaims, _ time.Time) { c["exp"] = nil },
		},
		{
			name:   "exp exactly at the current second",
			mutate: func(c jwt.MapClaims, now time.Time) { c["exp"] = now.Unix() },
		},
		{
			name:   "exp one second in the past",
			mutate: func(c jwt.MapClaims, now time.Time) { c["exp"] = now.Add(-time.Second).Unix() },
		},
		{
			name:   "exp thirty seconds in the past, well inside a typical skew allowance",
			mutate: func(c jwt.MapClaims, now time.Time) { c["exp"] = now.Add(-30 * time.Second).Unix() },
		},
		{
			name:   "exp at the unix epoch",
			mutate: func(c jwt.MapClaims, _ time.Time) { c["exp"] = 0 },
		},
		{
			name:   "exp before the unix epoch",
			mutate: func(c jwt.MapClaims, _ time.Time) { c["exp"] = -1 },
		},
		{
			name:   "exp five seconds ahead",
			mutate: func(c jwt.MapClaims, now time.Time) { c["exp"] = now.Add(5 * time.Second).Unix() },
			want:   true,
		},
		{
			name:   "nbf five seconds ahead",
			mutate: func(c jwt.MapClaims, now time.Time) { c["nbf"] = now.Add(5 * time.Second).Unix() },
		},
		{
			name:   "nbf one second ahead",
			mutate: func(c jwt.MapClaims, now time.Time) { c["nbf"] = now.Add(time.Second).Unix() },
		},
		{
			name:   "nbf exactly at the current second",
			mutate: func(c jwt.MapClaims, now time.Time) { c["nbf"] = now.Unix() },
			want:   true,
		},
		{
			name:   "nbf after exp",
			mutate: func(c jwt.MapClaims, now time.Time) { c["nbf"] = now.Add(time.Hour + time.Minute).Unix() },
		},
		{
			name: "an iat in the future cannot resurrect an expired token",
			mutate: func(c jwt.MapClaims, now time.Time) {
				c["iat"] = now.Add(time.Hour).Unix()
				c["exp"] = now.Add(-time.Second).Unix()
			},
		},
		{
			name:   "a quoted exp in the past is still in the past",
			mutate: func(c jwt.MapClaims, now time.Time) { c["exp"] = fmt.Sprint(now.Add(-time.Second).Unix()) },
		},
		{
			name:   "exp as a non-numeric string",
			mutate: func(c jwt.MapClaims, _ time.Time) { c["exp"] = "not-a-number" },
		},
		{
			name:   "exp as a quoted number too large for a float64",
			mutate: func(c jwt.MapClaims, _ time.Time) { c["exp"] = "1e999" },
		},
		{
			name:   "exp as an empty string",
			mutate: func(c jwt.MapClaims, _ time.Time) { c["exp"] = "" },
		},
		{
			name:   "exp as a boolean",
			mutate: func(c jwt.MapClaims, _ time.Time) { c["exp"] = true },
		},
		{
			name:   "exp as an array",
			mutate: func(c jwt.MapClaims, now time.Time) { c["exp"] = []int64{now.Add(time.Hour).Unix()} },
		},
		{
			name:   "exp as an object",
			mutate: func(c jwt.MapClaims, now time.Time) { c["exp"] = map[string]any{"exp": now.Unix()} },
		},
		{
			name:   "a quoted nbf in the future is still in the future",
			mutate: func(c jwt.MapClaims, now time.Time) { c["nbf"] = fmt.Sprint(now.Add(5 * time.Second).Unix()) },
		},
		{
			name:   "nbf as a non-numeric string",
			mutate: func(c jwt.MapClaims, _ time.Time) { c["nbf"] = "not-a-number" },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			now := time.Now()
			claims := advClaims(now, func(c jwt.MapClaims) { tc.mutate(c, now) })

			_, err := tm.ValidateAccessToken(ctx, advSign(t, jwt.SigningMethodHS256, secret, claims))
			switch {
			case tc.want && err != nil:
				t.Fatalf("Expected acceptance, got %v", err)
			case !tc.want && err == nil:
				t.Fatal("ACCEPTED a token outside its validity window")
			}
		})
	}
}

// TestJWT_ConstructorRefusesAsymmetricMethodWithSymmetricKey covers F-04
// (CWE-1188). SigningKey is a []byte and golang-jwt type-asserts an
// *rsa.PrivateKey or an *ecdsa.PrivateKey when it signs, so the documented
// RS256 and ES256 configurations were accepted by the constructor and failed at
// the first token minted -- in production, on the first sign-in after a deploy.
//
// A misconfiguration must be reported where it is made. The test also proves
// the constructor survives a hostile crypto.Signer: an implementation whose
// Public half is not what the method requires must produce an error, never a
// panic in a type assertion.
func TestJWT_ConstructorRefusesAsymmetricMethodWithSymmetricKey(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	otherRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	//nolint:gosec // G403: an undersized modulus is exactly what this case feeds the constructor.
	weakRSAKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(1024): %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}

	asymmetric := []jwt.SigningMethod{
		jwt.SigningMethodRS256, jwt.SigningMethodRS384, jwt.SigningMethodRS512,
		jwt.SigningMethodPS256, jwt.SigningMethodPS384, jwt.SigningMethodPS512,
		jwt.SigningMethodES256, jwt.SigningMethodES384, jwt.SigningMethodES512,
		jwt.SigningMethodEdDSA,
	}
	for _, method := range asymmetric {
		t.Run(method.Alg()+" with a []byte SigningKey", func(t *testing.T) {
			t.Parallel()

			tm, err := NewTokenManager(Config{
				UserStore:     storage.NewInMemoryUserStore(),
				SigningKey:    advSecret(t, 64),
				SigningMethod: method,
			})
			if err == nil {
				t.Fatalf("NewTokenManager accepted %s with a symmetric key", method.Alg())
			}
			if !errors.Is(err, ErrInvalidKeyConfig) {
				t.Fatalf("Expected ErrInvalidKeyConfig, got %v", err)
			}
			if tm != nil {
				t.Fatal("A manager escaped the constructor error and can be asked to mint")
			}
		})
	}

	hostile := []struct {
		name string
		cfg  Config
	}{
		{"RS256 with a signer that is not an RSA key", Config{PrivateKey: advBrokenSigner{public: nil}, SigningMethod: jwt.SigningMethodRS256}},
		{"ES256 with a signer holding an RSA public key", Config{PrivateKey: advBrokenSigner{public: rsaKey.Public()}, SigningMethod: jwt.SigningMethodES256}},
		{"EdDSA with a signer whose public half is nil", Config{PrivateKey: advBrokenSigner{public: nil}, SigningMethod: jwt.SigningMethodEdDSA}},
		{"EdDSA with an ECDSA signer", Config{PrivateKey: ecKey, SigningMethod: jwt.SigningMethodEdDSA}},
		{"RS256 with an undersized modulus", Config{PrivateKey: weakRSAKey, SigningMethod: jwt.SigningMethodRS256}},
		{"RS256 with somebody else's public key", Config{PrivateKey: rsaKey, PublicKey: otherRSAKey.Public(), SigningMethod: jwt.SigningMethodRS256}},
		{"RS256 with a public key of the wrong family", Config{PrivateKey: rsaKey, PublicKey: ecKey.Public(), SigningMethod: jwt.SigningMethodRS256}},
		{"ES256 with a P-384 key", Config{PrivateKey: advP384Key(t), SigningMethod: jwt.SigningMethodES256}},
		{"HS256 with an RSA private key", Config{SigningKey: nil, PrivateKey: rsaKey}},
		{"HS256 with both a secret and a private key", Config{SigningKey: advSecret(t, 32), PrivateKey: rsaKey}},
		{"the none signing method", Config{SigningKey: advSecret(t, 32), SigningMethod: jwt.SigningMethodNone}},
		{"no key material at all", Config{}},
	}
	for _, tc := range hostile {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := tc.cfg
			cfg.UserStore = storage.NewInMemoryUserStore()

			tm, err := NewTokenManager(cfg)
			if err == nil {
				t.Fatal("NewTokenManager accepted an unusable key configuration")
			}
			if !errors.Is(err, ErrInvalidKeyConfig) {
				t.Fatalf("Expected ErrInvalidKeyConfig, got %v", err)
			}
			if tm != nil {
				t.Fatal("A manager escaped the constructor error and can be asked to mint")
			}
		})
	}

	// The positive control: a correctly paired asymmetric configuration mints
	// and verifies, so the rejections above are about the pairing and not about
	// asymmetric signing being unreachable.
	t.Run("a correctly paired RS256 configuration mints and verifies", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		userStore := storage.NewInMemoryUserStore()
		user := advStoredUser(ctx, t, userStore, advUserID)
		tm := advManager(t, Config{
			UserStore:     userStore,
			PrivateKey:    rsaKey,
			PublicKey:     rsaKey.Public(),
			SigningMethod: jwt.SigningMethodRS256,
		})

		token, err := tm.GenerateAccessToken(ctx, user)
		if err != nil {
			t.Fatalf("GenerateAccessToken: %v", err)
		}
		if _, err := tm.ValidateAccessToken(ctx, token); err != nil {
			t.Fatalf("ValidateAccessToken: %v", err)
		}
	})
}

func advP384Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(P-384): %v", err)
	}
	return key
}

// TestJWT_UserMetadataNotLeakedIntoTokenClaims covers F-21 (CWE-200). The OIDC
// client stored the identity provider's entire raw claim set under
// Metadata["raw_claims"] and generateToken copied user.Metadata wholesale into
// the token, so every group membership and internal identifier the directory
// released ended up in a base64 blob held by the browser and echoed on every
// request.
//
// A JWT is encoded, not encrypted. The allow-list is exact-match by key: a
// prefix or substring match would leak the very keys an operator listed
// carefully.
func TestJWT_UserMetadataNotLeakedIntoTokenClaims(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	secret := advSecret(t, 32)

	user := &storage.User{
		ID:    advUserID,
		Email: advUserID + "@example.com",
		Metadata: map[string]any{
			"role":        "admin",
			"role_secret": "PRIVATE-role-secret",
			"roles":       []string{"PRIVATE-roles-list"},
			"ROLE":        "PRIVATE-upper-role",
			"raw_claims": map[string]any{
				"national_id": "PRIVATE-national-id",
				"groups":      []string{"PRIVATE-finance", "PRIVATE-payroll"},
				"ssn":         "PRIVATE-ssn",
			},
			"internal_directory_dn": "PRIVATE-cn=victim,ou=people",
			"iss":                   "shadow-issuer",
			"exp":                   "shadow-exp",
			"type":                  "shadow-type",
			"uid":                   "shadow-uid",
		},
	}

	tests := []struct {
		name      string
		allowlist []string
		wantKeys  []string
	}{
		{name: "no allow-list emits no metadata at all"},
		{name: "an allow-list naming absent keys emits nothing", allowlist: []string{"department", "employee_number"}},
		{name: "an exact key is copied and its neighbors are not", allowlist: []string{"role"}, wantKeys: []string{"role"}},
		{name: "a key that shadows a registered claim stays inside the metadata object", allowlist: []string{"iss", "exp", "type", "uid"}, wantKeys: []string{"iss", "exp", "type", "uid"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			userStore := storage.NewInMemoryUserStore()
			tm := advManager(t, Config{
				UserStore:         userStore,
				SigningKey:        secret,
				Issuer:            advIssuer,
				MetadataAllowlist: tc.allowlist,
			})

			token, err := tm.GenerateAccessToken(ctx, user)
			if err != nil {
				t.Fatalf("GenerateAccessToken: %v", err)
			}

			claims, err := tm.ValidateAccessToken(ctx, token)
			if err != nil {
				t.Fatalf("ValidateAccessToken: %v", err)
			}
			if len(claims.Metadata) != len(tc.wantKeys) {
				t.Fatalf("Expected metadata keys %v, got %v", tc.wantKeys, claims.Metadata)
			}
			for _, key := range tc.wantKeys {
				if _, ok := claims.Metadata[key]; !ok {
					t.Errorf("Expected allow-listed key %q in the metadata claim", key)
				}
			}

			// The registered claims must be the manager's, never the user's.
			if claims.Issuer != advIssuer {
				t.Errorf("Expected iss %q, got %q", advIssuer, claims.Issuer)
			}
			if claims.Type != AccessToken {
				t.Errorf("Expected type %q, got %q", AccessToken, claims.Type)
			}
			if claims.UserID != user.ID {
				t.Errorf("Expected uid %q, got %q", user.ID, claims.UserID)
			}
			if claims.ExpiresAt == nil || !claims.ExpiresAt.After(time.Now()) {
				t.Errorf("Expected a live exp, got %v", claims.ExpiresAt)
			}

			// Anyone holding the token can read the payload; nothing the
			// operator did not name may be in it.
			advPayloadOmits(t, token, "PRIVATE", "raw_claims", "national_id", "groups", "ssn", "internal_directory_dn")
		})
	}
}

// advPayloadOmits decodes the payload the way any holder of the token can and
// fails if a forbidden substring survived into it.
func advPayloadOmits(t *testing.T, token string, forbidden ...string) {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("Expected 3 segments, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("Failed to decode the payload: %v", err)
	}
	for _, needle := range forbidden {
		if strings.Contains(string(payload), needle) {
			t.Errorf("The token payload leaks %q: %s", needle, payload)
		}
	}
}

// TestJWT_RevokedRefreshTokenCannotAuthenticateAnywhere pins revocation
// completeness: once a refresh token is revoked it must be dead on every path
// that turns a token into authority, and revoking one credential must not
// revoke a bystander's.
//
// It also carries the F-02 assertion in its revocation form. A refresh token is
// the credential a user revokes precisely because they believe it is stolen; if
// it is still accepted as a bearer token, revocation is a formality.
func TestJWT_RevokedRefreshTokenCannotAuthenticateAnywhere(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	userStore := storage.NewInMemoryUserStore()
	tokenStore := storage.NewInMemoryTokenStore()
	victim := advStoredUser(ctx, t, userStore, advUserID)
	bystander := advStoredUser(ctx, t, userStore, "user-bystander")

	tm := advManager(t, Config{
		UserStore:  userStore,
		TokenStore: tokenStore,
		SigningKey: advSecret(t, 32),
		Issuer:     advIssuer,
		Audience:   []string{advAudience},
	})

	mint := func(user *storage.User) *TokenPair {
		t.Helper()

		pair, err := tm.GenerateTokenPair(ctx, user)
		if err != nil {
			t.Fatalf("GenerateTokenPair(%s): %v", user.ID, err)
		}
		return pair
	}
	assertDead := func(label string, pair *TokenPair) {
		t.Helper()

		claims, err := tm.ValidateRefreshToken(ctx, pair.RefreshToken)
		if err == nil {
			t.Errorf("%s: a revoked refresh token still validates", label)
		}
		if claims != nil {
			t.Errorf("%s: a revoked refresh token still yields claims %+v", label, claims)
		}
		if !errors.Is(err, ErrTokenRevoked) && !errors.Is(err, storage.ErrTokenRevoked) {
			t.Errorf("%s: expected a revocation error, got %v", label, err)
		}
		if _, err := tm.RefreshAccessToken(ctx, pair.RefreshToken); err == nil {
			t.Errorf("%s: a revoked refresh token still mints access tokens", label)
		}
	}
	assertAlive := func(label string, pair *TokenPair) {
		t.Helper()

		if _, err := tm.ValidateRefreshToken(ctx, pair.RefreshToken); err != nil {
			t.Errorf("%s: an unrevoked refresh token was refused: %v", label, err)
		}
	}

	victimFirst, victimSecond := mint(victim), mint(victim)
	bystanderPair := mint(bystander)

	if err := tm.RevokeRefreshToken(ctx, victimFirst.RefreshToken); err != nil {
		t.Fatalf("RevokeRefreshToken: %v", err)
	}
	assertDead("after a single revocation", victimFirst)
	assertAlive("the victim's other token", victimSecond)
	assertAlive("the bystander", bystanderPair)

	// A revoked token presented to the revoke path again must not resurrect it.
	if err := tm.RevokeRefreshToken(ctx, victimFirst.RefreshToken); err != nil {
		t.Fatalf("Re-revoking must be idempotent, got %v", err)
	}
	assertDead("after a replayed revocation", victimFirst)

	// F-02 in its revocation form: the dead credential must not be usable as a
	// bearer token, and neither must a live one.
	for _, pair := range []*TokenPair{victimFirst, victimSecond} {
		if claims, err := tm.ValidateToken(ctx, pair.RefreshToken); err == nil {
			t.Errorf("A refresh token authorized a protected route: %+v", claims)
		}
	}

	if err := tm.RevokeAllUserTokens(ctx, victim.ID); err != nil {
		t.Fatalf("RevokeAllUserTokens: %v", err)
	}
	assertDead("after RevokeAllUserTokens", victimFirst)
	assertDead("after RevokeAllUserTokens", victimSecond)
	assertAlive("the bystander after the victim's mass revocation", bystanderPair)

	// A token minted after the mass revocation must work: revocation is an
	// event, not a permanent state on the user.
	assertAlive("a token minted after the mass revocation", mint(victim))
}

// TestJWT_TruncatedOrExtendedSigningKeyRejected pins the key binding itself.
// RFC 7515 section 5.2 makes acceptance conditional on a signature that
// verifies under the verifier's own key, so a secret that merely shares a
// prefix with the real one -- a truncated environment variable, a key
// derivation that returns fewer bytes than it promised, a trailing newline
// picked up from a mounted file -- must not authenticate anybody.
//
// The asymmetric half pins the sign/verify split introduced with F-04: the
// manager must verify against the public half of its own key pair and nothing
// else.
func TestJWT_TruncatedOrExtendedSigningKeyRejected(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	secret := advSecret(t, 32)
	userStore := storage.NewInMemoryUserStore()
	user := advStoredUser(ctx, t, userStore, advUserID)

	tm := advManager(t, Config{
		UserStore:  userStore,
		TokenStore: storage.NewInMemoryTokenStore(),
		SigningKey: secret,
		Issuer:     advIssuer,
	})

	reversed := make([]byte, len(secret))
	for i, b := range secret {
		reversed[len(secret)-1-i] = b
	}

	keys := []struct {
		name string
		key  []byte
	}{
		{"the secret with its last byte removed", secret[:len(secret)-1]},
		{"the first half of the secret", secret[:len(secret)/2]},
		{"the secret without its first byte", secret[1:]},
		{"the secret with a newline appended", append(append([]byte{}, secret...), '\n')},
		{"the secret with a random byte appended", append(append([]byte{}, secret...), advSecret(t, 1)...)},
		{"the secret doubled", append(append([]byte{}, secret...), secret...)},
		{"the secret reversed", reversed},
		{"the secret hex-encoded", []byte(fmt.Sprintf("%x", secret))},
		{"the secret base64-encoded", []byte(base64.StdEncoding.EncodeToString(secret))},
		{"an empty secret", []byte{}},
		{"one NUL byte", []byte{0}},
	}
	for _, tc := range keys {
		t.Run("a token signed with "+tc.name, func(t *testing.T) {
			t.Parallel()

			now := time.Now()
			claims := advClaims(now, func(c jwt.MapClaims) { c["iss"] = advIssuer })
			advRejectOnEverySurface(ctx, t, tm, advSign(t, jwt.SigningMethodHS256, tc.key, claims))
		})
	}

	// RFC 2104 pads an HMAC key shorter than the hash block size with zero
	// bytes, so a 32-byte secret and that same secret with trailing NULs are
	// literally the same key. It is recorded here rather than asserted as a
	// rejection, because a test demanding one would be demanding that the
	// library break HMAC. The operational consequence is that trailing-byte
	// differences are not a safe way to distinguish two secrets -- truncation,
	// covered above, is the direction that actually changes the key.
	t.Run("trailing NUL bytes are absorbed by the HMAC key padding", func(t *testing.T) {
		t.Parallel()

		now := time.Now()
		claims := advClaims(now, func(c jwt.MapClaims) { c["iss"] = advIssuer })
		padded := advSign(t, jwt.SigningMethodHS256, append(append([]byte{}, secret...), 0, 0, 0), claims)

		verified, err := tm.ValidateAccessToken(ctx, padded)
		if err != nil {
			t.Fatalf("RFC 2104 key padding makes this the same key; expected acceptance, got %v", err)
		}
		if verified.UserID != advUserID {
			t.Fatalf("Expected uid %q, got %q", advUserID, verified.UserID)
		}
	})

	t.Run("a manager holding a truncated secret refuses genuine tokens", func(t *testing.T) {
		t.Parallel()

		token, err := tm.GenerateAccessToken(ctx, user)
		if err != nil {
			t.Fatalf("GenerateAccessToken: %v", err)
		}

		truncated := advManager(t, Config{
			UserStore:  userStore,
			SigningKey: secret[:len(secret)-1],
			Issuer:     advIssuer,
		})
		if _, err := truncated.ValidateAccessToken(ctx, token); err == nil {
			t.Fatal("A manager with a truncated secret accepted a token minted under the full one")
		}
	})

	t.Run("a mangled signature on a genuine token", func(t *testing.T) {
		t.Parallel()

		token, err := tm.GenerateAccessToken(ctx, user)
		if err != nil {
			t.Fatalf("GenerateAccessToken: %v", err)
		}
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Fatalf("Expected 3 segments, got %d", len(parts))
		}
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatalf("Failed to decode the signature: %v", err)
		}

		flipped := append([]byte{}, sig...)
		flipped[0] ^= 0x01
		truncatedSig := sig[:len(sig)-1]
		extendedSig := append(append([]byte{}, sig...), 0)

		mangled := map[string]string{
			"one flipped bit":            base64.RawURLEncoding.EncodeToString(flipped),
			"a signature one byte short": base64.RawURLEncoding.EncodeToString(truncatedSig),
			"a signature one byte long":  base64.RawURLEncoding.EncodeToString(extendedSig),
			"an empty signature":         "",
			"a padded re-encoding":       base64.URLEncoding.EncodeToString(sig),
			"the header's signature":     parts[0],
		}
		for name, sig := range mangled {
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				advRejectOnEverySurface(ctx, t, tm, parts[0]+"."+parts[1]+"."+sig)
			})
		}
	})

	t.Run("an asymmetric manager verifies only against its own public half", func(t *testing.T) {
		t.Parallel()

		ours, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey: %v", err)
		}
		theirs, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey: %v", err)
		}

		asym := advManager(t, Config{
			UserStore:     userStore,
			TokenStore:    storage.NewInMemoryTokenStore(),
			PrivateKey:    ours,
			SigningMethod: jwt.SigningMethodRS256,
			Issuer:        advIssuer,
		})

		now := time.Now()
		claims := advClaims(now, func(c jwt.MapClaims) { c["iss"] = advIssuer })
		advRejectOnEverySurface(ctx, t, asym, advSign(t, jwt.SigningMethodRS256, theirs, claims))

		if _, err := asym.ValidateAccessToken(ctx, advSign(t, jwt.SigningMethodRS256, ours, claims)); err != nil {
			t.Fatalf("A token signed with our own key must validate: %v", err)
		}
	})
}

// TestJWT_MalformedTokenShapesRejectedWithoutPanic is the fuzz-shaped floor
// under every other test here: a credential arrives from the network, so no
// input may panic, hang, or return claims. It also pins two decoding
// properties that are security-relevant rather than cosmetic.
//
// Base64 padding: RFC 7515 section 2 defines a JOSE segment as base64url
// WITHOUT padding, and accepting a padded segment gives the same token two
// encodings, which is the multiplicity of encodings that RFC 8725 warns
// about for anything that deduplicates or blocklists tokens by string.
//
// kid: RFC 8725 section 3.10 treats a received kid as untrusted input. This
// verifier holds exactly one key and must never consult the header to choose
// one, so a kid naming a traversal path changes nothing about the verdict.
func TestJWT_MalformedTokenShapesRejectedWithoutPanic(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	secret := advSecret(t, 32)
	userStore := storage.NewInMemoryUserStore()
	user := advStoredUser(ctx, t, userStore, advUserID)

	tm := advManager(t, Config{
		UserStore:  userStore,
		TokenStore: storage.NewInMemoryTokenStore(),
		SigningKey: secret,
		Issuer:     advIssuer,
	})

	genuine, err := tm.GenerateAccessToken(ctx, user)
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}
	parts := strings.Split(genuine, ".")
	if len(parts) != 3 {
		t.Fatalf("Expected 3 segments, got %d", len(parts))
	}

	// A header segment large enough that a decoder without a ceiling notices.
	oversizedHeader := base64.RawURLEncoding.EncodeToString(
		[]byte(`{"alg":"HS256","typ":"JWT","x":"` + strings.Repeat("A", 1<<20) + `"}`))
	deepHeader := base64.RawURLEncoding.EncodeToString(
		[]byte(strings.Repeat(`{"a":`, 20000) + `1` + strings.Repeat(`}`, 20000)))

	tokens := map[string]string{
		"the empty string":                    "",
		"a single dot":                        ".",
		"two dots":                            "..",
		"three dots":                          "...",
		"only whitespace":                     "   ",
		"a bearer prefix left attached":       "Bearer " + genuine,
		"a leading space":                     " " + genuine,
		"an embedded NUL":                     genuine[:10] + "\x00" + genuine[10:],
		"the genuine token truncated by half": genuine[:len(genuine)/2],
		"the header alone":                    parts[0],
		"header and payload only":             parts[0] + "." + parts[1],
		"a fourth segment appended":           genuine + "." + parts[2],
		"the segments reordered":              parts[2] + "." + parts[1] + "." + parts[0],
		"the payload swapped for the header":  parts[0] + "." + parts[0] + "." + parts[2],
		"padded base64 segments":              base64.URLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`)) + "." + parts[1] + "." + parts[2],
		"standard base64 with plus and slash": "e30+/w." + parts[1] + "." + parts[2],
		"a header that is not JSON":           base64.RawURLEncoding.EncodeToString([]byte("not json")) + "." + parts[1] + "." + parts[2],
		"a header that is a JSON array":       base64.RawURLEncoding.EncodeToString([]byte(`["HS256"]`)) + "." + parts[1] + "." + parts[2],
		"a payload that is not JSON":          parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + "." + parts[2],
		"a payload that is a JSON array":      parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`[]`)) + "." + parts[2],
		"a 1 MiB header":                      oversizedHeader + "." + parts[1] + "." + parts[2],
		"a deeply nested header":              deepHeader + "." + parts[1] + "." + parts[2],
		"invalid base64 in every segment":     "!!!.???.***",
		"unicode in the segments":             "héader.payloäd.sig",
	}
	for name, token := range tokens {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			advRejectOnEverySurface(ctx, t, tm, token)
		})
	}

	// Go's base64 decoder ignores CR and LF, so "<token>\n" and even a token
	// with newlines injected inside a segment decode to the same bytes and are
	// accepted. RFC 8725 calls a multiplicity of encodings for one token out
	// as a hazard: a caller that denylists, deduplicates or fingerprints a
	// token by its STRING can be walked around with a newline. This library
	// keys revocation on the jti rather than on the string, so the invariant
	// that has to hold is that every encoding resolves to the same identity --
	// a divergence would be a token-confusion primitive rather than a
	// housekeeping wart.
	t.Run("alternate encodings of one token resolve to one identity", func(t *testing.T) {
		t.Parallel()

		base, err := tm.ValidateAccessToken(ctx, genuine)
		if err != nil {
			t.Fatalf("ValidateAccessToken: %v", err)
		}

		encodings := map[string]string{
			"a trailing newline":            genuine + "\n",
			"a trailing carriage return":    genuine + "\r",
			"a newline inside the payload":  parts[0] + "." + parts[1][:4] + "\n" + parts[1][4:] + "." + parts[2],
			"newlines around every segment": parts[0] + "\n." + parts[1] + "\n." + parts[2] + "\n",
		}
		for name, encoded := range encodings {
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				claims, err := tm.ValidateAccessToken(ctx, encoded)
				if err != nil {
					return // rejected outright is the stronger outcome
				}
				if claims.UserID != base.UserID || claims.Type != base.Type {
					t.Fatalf("A re-encoding of one token resolved to a different identity: %+v vs %+v", claims, base)
				}
			})
		}
	})

	t.Run("a kid never selects key material", func(t *testing.T) {
		t.Parallel()

		now := time.Now()
		claims := advClaims(now, func(c jwt.MapClaims) { c["iss"] = advIssuer })

		for _, kid := range []string{"../../../../etc/passwd", "/dev/null", "file:///dev/null", "' OR 1=1 --", strings.Repeat("k", 1<<16)} {
			// Signed with a key the manager does not hold: no kid may talk it
			// into fetching or deriving one.
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			token.Header["kid"] = kid
			signed, err := token.SignedString(advSecret(t, 32))
			if err != nil {
				t.Fatalf("SignedString: %v", err)
			}
			if _, foreignErr := tm.ValidateAccessToken(ctx, signed); foreignErr == nil {
				t.Errorf("ACCEPTED a foreign-key token carrying kid %q", kid)
			}

			// Signed with the real secret: the kid is inert, not fatal.
			token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			token.Header["kid"] = kid
			signed, err = token.SignedString(secret)
			if err != nil {
				t.Fatalf("SignedString: %v", err)
			}
			if _, genuineErr := tm.ValidateAccessToken(ctx, signed); genuineErr != nil {
				t.Errorf("A genuine token was refused because of its kid %q: %v", kid, genuineErr)
			}
		}
	})
}

// TestJWT_DeeplyPaddedTokenRejectedWithoutUnboundedAllocation is the
// decode-time resource guard: a credential that is 99.99 % delimiter must cost
// the verifier nothing to refuse.
//
// This is the class disclosed against golang-jwt as CVE-2025-30204 and fixed in
// v5.2.2, where the token was split on every "." before anything checked how
// many segments a JWT is allowed to have, so an attacker-supplied string
// allocated a slice header per delimiter. The guard lives in the dependency, so
// this test is the regression fence around the dependency floor: it fails if
// the module is downgraded past the fix.
//
// The measurement is a TotalAlloc delta rather than a duration, because a
// wall-clock budget is a flake on a loaded CI runner and an allocation budget
// is not. The test is deliberately NOT parallel: a concurrent test allocating
// in the same process would be counted against it.
func TestJWT_DeeplyPaddedTokenRejectedWithoutUnboundedAllocation(t *testing.T) {
	ctx := context.Background()
	tm := advManager(t, Config{
		SigningKey: advSecret(t, 32),
		Issuer:     advIssuer,
	})

	const (
		delimiters = 200_000
		// A slice header per delimiter is 200_000 * 16 bytes = 3.2 MiB before
		// the segments themselves. 256 KiB leaves an order of magnitude of
		// headroom over what a correct implementation needs (it stops at the
		// third delimiter) and an order of magnitude below what the vulnerable
		// one consumed.
		maxAlloc = 256 << 10
	)

	var b strings.Builder
	b.Grow(2*delimiters + 64)
	b.WriteString(base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`)))
	for range delimiters {
		b.WriteString(".x")
	}
	token := b.String()

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	claims, err := tm.ValidateToken(ctx, token)

	runtime.ReadMemStats(&after)

	if err == nil {
		t.Fatal("ACCEPTED a token with 200000 segments")
	}
	if claims != nil {
		t.Fatalf("Returned claims for a malformed token: %+v", claims)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > maxAlloc {
		t.Fatalf("Rejecting a %d-segment token allocated %d bytes, over the %d byte budget: the parser is walking the whole input before counting segments",
			delimiters, allocated, maxAlloc)
	}
}
