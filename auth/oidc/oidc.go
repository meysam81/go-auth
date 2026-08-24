// Package oidc provides OpenID Connect and OAuth2 relying-party authentication
// for single sign-on.
//
// # Security model
//
// A flow started with [Client.GetAuthorizationURLWithBinding] is protected by
// four independent controls, every one of which is verified before a single
// claim is believed:
//
//   - state, a one-time server-side record proving the callback belongs to a
//     flow this process started;
//   - a browser binding, a second high-entropy value handed to the caller for
//     storage in a cookie and kept server-side only as a SHA-256 digest, which
//     proves the callback reached the user agent that began the flow
//     (finding F-16, CWE-352, login CSRF);
//   - PKCE S256, which makes an intercepted authorization code useless to
//     anyone who does not also hold the verifier (finding F-17,
//     RFC 9700 section 2.1.1, which requires PKCE for every client type);
//   - a nonce, which makes an ID token captured from one authentication
//     unusable in another (finding F-18, OIDC Core section 3.1.3.7).
//
// A flow started with the older [Client.GetAuthorizationURL] carries state,
// PKCE and a nonce but no browser binding, because that entry point has no way
// to return the binding value to the caller. The binding is therefore OPT-IN:
// an application still calling the unbound pair has the login-CSRF hole of
// finding F-16 open, and both entry points are deprecated for that reason.
//
// # What the state store must persist
//
// Three of those four controls live in the [storage.OIDCState] record between
// the authorization request and the callback, and the package cannot enforce a
// control a store did not keep. Each one is therefore written twice: into its
// typed field on the record — [storage.OIDCState].CodeVerifier, BindingHash and
// Nonce — and into a reserved [StateMetadataPrefix] key in the record's
// Metadata map, which is where a store written against v1.1.1 (before those
// fields existed) still has somewhere to put it. The callback reads the typed
// field first and the metadata copy second.
//
// A record that comes back with a control missing from both places is a record
// a store silently dropped, and this package refuses it with
// [ErrStateControlMissing] rather than continuing without the control. That is
// the whole point of writing it twice: absence is never read as "this flow did
// not have one". A flow deliberately started without a browser binding records
// [StateBindingUnbound], so even "no binding" is a value the store must carry
// rather than an absence anyone can manufacture.
//
// # Identity belongs to the application
//
// This package verifies an assertion and reports what the provider said. It is
// not able to decide which human that assertion refers to: only the
// application knows its own tenancy, provisioning and account-linking rules.
// The find-or-create behavior reachable through [Config.UserStore] is retained
// for compatibility, is deliberately conservative, and is removed in v2. New
// code should leave UserStore nil and resolve identity from
// [CallbackResult.UserInfo].
//
// # Network egress
//
// Token exchange and user-info retrieval are performed with [Config.HTTPClient]
// (see finding F-20, CWE-918). The package bounds the request with a timeout
// and the response with a size limit, and it deliberately does not ship a
// dialer that refuses private address ranges: which addresses a process may
// reach is infrastructure policy owned by the application, not by a library.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/meysam81/go-auth/storage"
	"golang.org/x/oauth2"
)

var (
	// ErrInvalidState is returned when the OAuth2 state parameter is invalid.
	ErrInvalidState = errors.New("invalid state parameter")

	// ErrProviderNotFound is returned when a provider isn't configured.
	ErrProviderNotFound = errors.New("provider not found")

	// ErrProviderMisconfigured is returned when a registered provider does not
	// supply the OAuth2 configuration the flow needs.
	ErrProviderMisconfigured = errors.New("provider is misconfigured")

	// ErrExchangeFailed is returned when the OAuth2 code exchange fails.
	ErrExchangeFailed = errors.New("failed to exchange authorization code")

	// ErrUserInfoFailed is returned when fetching user info fails.
	ErrUserInfoFailed = errors.New("failed to fetch user info")

	// ErrCorruptState is returned when a state record read back from the store
	// does not have the shape this package wrote, which means the record was
	// truncated, rewritten by another writer, or produced by another library.
	// It is never treated as "no value present": a control that silently
	// disappears is a control that can be removed by an attacker.
	ErrCorruptState = errors.New("state record is malformed")

	// ErrStateControlMissing is returned when a state record comes back without
	// a control this package is known to have written into it — the PKCE
	// verifier, the browser-binding marker, or the nonce of an OIDC flow —
	// in either the typed [storage.OIDCState] field or the reserved metadata
	// key that mirrors it.
	//
	// It means the store did not persist what it was given, which is
	// indistinguishable from an attacker having removed the control. Treating
	// it as "this flow had no such control" is how a store with one column per
	// field it recognized turned PKCE, the browser binding and the nonce into
	// decoration while every conformance test still passed.
	ErrStateControlMissing = errors.New("state record is missing a control this package wrote")

	// ErrMissingBinding is returned when the flow was started with
	// [Client.GetAuthorizationURLWithBinding] but the callback presented no
	// binding value. See finding F-16.
	ErrMissingBinding = errors.New("state binding value was not presented")

	// ErrBindingMismatch is returned when the presented binding value does not
	// match the one issued when the flow started, which means the callback was
	// delivered to a different user agent. See finding F-16.
	ErrBindingMismatch = errors.New("state binding value does not match")

	// ErrMissingNonce is returned when a nonce was requested at authorization
	// time and the ID token carries no nonce claim. See finding F-18.
	ErrMissingNonce = errors.New("id token is missing the requested nonce claim")

	// ErrNonceMismatch is returned when the ID token's nonce claim is not the
	// value this process requested, which means the token was minted for a
	// different authentication. See finding F-18.
	ErrNonceMismatch = errors.New("id token nonce does not match the requested value")

	// ErrMissingSubject is returned when the provider asserts no subject
	// identifier. sub is REQUIRED by OIDC Core section 2 and is the only
	// immutable identity key an assertion carries. See finding F-01.
	ErrMissingSubject = errors.New("provider asserted no subject identifier")

	// ErrMissingEmail is returned when identity resolution was requested but
	// the provider asserted no email address. This package keys its
	// compatibility find-or-create path on the email address, so an absent one
	// cannot resolve an identity and would otherwise mint an unbounded number
	// of accounts. See finding F-01.
	ErrMissingEmail = errors.New("provider asserted no email address")

	// ErrEmailNotVerified is returned when the provider asserts an email
	// address it has not verified. Treating such a claim as an identity is the
	// defect published as CVE-2023-28131 ("nOAuth") and described in
	// RFC 9700 section 4. See finding F-01.
	ErrEmailNotVerified = errors.New("provider asserted an unverified email address")

	// ErrAccountLinkRequired is returned when an account already exists for the
	// asserted email address but was not created by this provider, or does not
	// carry this provider's subject identifier. Adopting it would let any
	// identity provider that can assert an arbitrary email claim take the
	// account over. Supply [Config.LinkPolicy] to authorize the link in
	// application code. See finding F-01.
	ErrAccountLinkRequired = errors.New("existing account requires an explicit link decision")

	// ErrAccountCreationRefused is returned when a verified assertion names no
	// existing account and [Config.CreatePolicy] did not authorize provisioning
	// one — either because it is nil, which is the default, or because it
	// returned false.
	//
	// Provisioning on a provider's say-so alone lets any identity provider the
	// deployment has configured squat an address it does not own: it asserts
	// cfo@victim-corp.example with email_verified true, the library mints the
	// account, and the real owner is met with [ErrAccountLinkRequired] forever
	// after. Only the application knows which addresses a given connection is
	// authoritative for, so only the application can answer. See finding F-01.
	ErrAccountCreationRefused = errors.New("account creation was not authorized")

	// ErrReservedMetadataKey is returned when [AuthURLOptions].Metadata carries
	// a key under [StateMetadataPrefix], which this package reserves for the
	// PKCE verifier and the browser-binding digest.
	ErrReservedMetadataKey = errors.New("state metadata uses a reserved key prefix")

	// ErrResponseTooLarge is returned when a provider response exceeds
	// [DefaultMaxResponseBytes]. It applies to the client returned by
	// [DefaultHTTPClient]; a caller-supplied client sets its own limits.
	ErrResponseTooLarge = errors.New("provider response exceeded the maximum allowed size")
)

const (
	// StateMetadataPrefix is the key prefix this package reserves inside
	// [storage.OIDCState].Metadata. Keys under it are written and read by the
	// library, are stripped from [CallbackResult].Metadata, and are rejected
	// with [ErrReservedMetadataKey] when supplied by the caller.
	StateMetadataPrefix = "go-auth/"

	// StateMetadataKeyPKCEVerifier is the state metadata key mirroring
	// [storage.OIDCState].CodeVerifier, the PKCE code verifier held between
	// authorization and callback (finding F-17). It is a secret for the
	// lifetime of the flow: a state store must be at least as well protected as
	// a session store.
	StateMetadataKeyPKCEVerifier = StateMetadataPrefix + "pkce_verifier"

	// StateMetadataKeyBinding is the state metadata key mirroring
	// [storage.OIDCState].BindingHash: the SHA-256 digest, base64url-encoded
	// without padding, of the browser-binding value returned in
	// [AuthorizationRequest].Binding (finding F-16), or [StateBindingUnbound]
	// for a flow started without one. Only the digest is stored, so a reader of
	// the state store cannot replay it.
	StateMetadataKeyBinding = StateMetadataPrefix + "state_binding"

	// StateMetadataKeyNonce is the state metadata key mirroring
	// [storage.OIDCState].Nonce, the value an OIDC provider must echo in the ID
	// token (finding F-18).
	StateMetadataKeyNonce = StateMetadataPrefix + "nonce"

	// StateBindingUnbound is recorded in place of a binding digest when a flow
	// is started through [Client.GetAuthorizationURL], which cannot hand a
	// binding value back to the caller.
	//
	// An explicit marker rather than an empty field is what makes the control
	// auditable: without it, "this flow was deliberately unbound" and "the
	// store dropped the digest" are the same empty string, and the second one
	// silently reopens the login CSRF of finding F-16. It cannot be confused
	// with a real digest, which is always 43 base64url characters, and a caller
	// cannot plant it because the key it lives under is reserved.
	StateBindingUnbound = "unbound"

	// UserMetadataKeyProviderSubject is the [storage.User].Metadata key
	// mirroring [storage.User].ProviderSubject, the provider's subject
	// identifier. It is the value compared against a later assertion before an
	// existing account is adopted (finding F-01).
	UserMetadataKeyProviderSubject = "provider_sub"

	// BindingCookieName is the recommended cookie name for
	// [AuthorizationRequest].Binding. The __Host- prefix makes the browser
	// refuse the cookie unless it is Secure, has Path=/ and carries no Domain
	// attribute, which stops a sibling subdomain from setting it. Set it
	// HttpOnly, SameSite=Lax, and with a Max-Age no longer than
	// [DefaultStateTTL].
	BindingCookieName = "__Host-go-auth-oidc-binding"

	// DefaultStateTTL is how long an authorization request may stay
	// outstanding before its state record expires.
	DefaultStateTTL = 10 * time.Minute

	// DefaultHTTPTimeout bounds a token exchange or user-info request made with
	// the client from [DefaultHTTPClient]. See finding F-20.
	DefaultHTTPTimeout = 15 * time.Second

	// DefaultMaxResponseBytes bounds a provider response read through the
	// client from [DefaultHTTPClient]. Token, discovery and JWKS documents are
	// orders of magnitude smaller; a hostile body is not. See finding F-20.
	DefaultMaxResponseBytes = 1 << 20

	// stateEntropyBytes, bindingEntropyBytes and nonceEntropyBytes are all 256
	// bits, which is far above the 128-bit floor RFC 9700 section 2.1 sets for
	// a value whose only job is to be unguessable.
	stateEntropyBytes   = 32
	bindingEntropyBytes = 32
	nonceEntropyBytes   = 32
)

// Provider defines the interface for an OIDC/OAuth2 provider.
type Provider interface {
	// Name returns the provider's unique name (e.g., "google", "github").
	Name() string

	// GetOAuth2Config returns the OAuth2 configuration.
	GetOAuth2Config() *oauth2.Config

	// GetOIDCProvider returns the OIDC provider (nil for OAuth2-only providers).
	GetOIDCProvider() *oidc.Provider

	// ExtractUserInfo extracts user information from the OAuth2 token.
	// For OIDC providers, this validates the ID token and extracts claims.
	// For OAuth2-only providers (e.g., GitHub), this calls the user info endpoint.
	ExtractUserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error)
}

// UserInfo represents user information extracted from an OIDC/OAuth2 provider.
type UserInfo struct {
	Subject       string                 `json:"sub"` // Unique user ID from provider
	Email         string                 `json:"email"`
	EmailVerified bool                   `json:"email_verified"`
	Name          string                 `json:"name,omitempty"`
	Username      string                 `json:"username,omitempty"`
	Picture       string                 `json:"picture,omitempty"`
	Provider      string                 `json:"provider"` // Provider name
	RawClaims     map[string]interface{} `json:"raw_claims,omitempty"`
}

// LinkPolicy authorizes attaching a provider assertion to an existing account
// that the library refuses to adopt on its own.
//
// It is called only when an account already exists for the asserted email
// address and the library will not adopt it on its own: it was created by a
// different provider, or it carries a different subject identifier — in other
// words, exactly when silent adoption would be the CVE-2023-28131 defect — or
// it predates subject recording entirely and is about to be pinned to this
// assertion. Returning true accepts the link; returning false yields
// [ErrAccountLinkRequired]; a returned error aborts the callback.
//
// An implementation is expected to have proved something the library cannot
// see: that the person behind this flow already controls the existing account.
type LinkPolicy func(ctx context.Context, existing *storage.User, info *UserInfo) (bool, error)

// CreatePolicy authorizes provisioning a NEW account from a provider assertion.
//
// It is the creation-side counterpart of [LinkPolicy], and it is called only
// after every control in this package has passed: the state, the browser
// binding, PKCE, the nonce, a present subject, and an email address the
// provider says it verified. What it decides is the one question none of those
// answers — whether this connection may speak for this email address at all.
//
// Returning true provisions the account; returning false yields
// [ErrAccountCreationRefused]; a returned error aborts the callback.
type CreatePolicy func(ctx context.Context, info *UserInfo) (bool, error)

// AllowAccountCreation is a [CreatePolicy] that provisions an account for every
// assertion this package has already verified. It restores, in one line, the
// behavior of releases that had no creation-side check at all.
//
// It is the right answer only where every configured provider is trusted to
// speak for every email domain it asserts — a single first-party IdP over a
// directory the deployment owns. It is the wrong answer for anything that lets
// a customer bring their own connection, because there the email claim is
// chosen by that customer's administrator. See finding F-01.
func AllowAccountCreation(context.Context, *UserInfo) (bool, error) {
	return true, nil
}

// Client handles OIDC authentication flows.
type Client struct {
	providers      map[string]Provider
	userStore      storage.UserStore
	stateStore     storage.OIDCStateStore
	redirectURL    string // Default redirect URL
	linkPolicy     LinkPolicy
	createPolicy   CreatePolicy
	httpClient     *http.Client
	claimAllowlist []string
}

// Config configures the OIDC client.
type Config struct {
	Providers []Provider

	// UserStore, when set, enables the compatibility find-or-create path:
	// [Client.HandleCallback] resolves or creates a [storage.User] and reports
	// it in [CallbackResult].User. Leave it nil to receive verified claims
	// only, which is the v2 shape.
	//
	// Deprecated: identity is the application's to own, not a library's. v2
	// removes user creation and lookup from this package. Leave this nil and
	// resolve the identity yourself from [CallbackResult].UserInfo.
	UserStore storage.UserStore

	StateStore  storage.OIDCStateStore
	RedirectURL string // Optional: default redirect URL after authentication

	// LinkPolicy optionally authorizes adopting an existing account that this
	// package would otherwise refuse. Nil means refuse, which is the safe
	// default. See finding F-01.
	LinkPolicy LinkPolicy

	// CreatePolicy authorizes provisioning a new account when a verified
	// assertion matches none. Nil REFUSES creation with
	// [ErrAccountCreationRefused].
	//
	// Refusing is the default because the library cannot answer the question
	// creation asks. An assertion carries an email address and a flag saying
	// the provider verified it; neither tells this package whether the
	// connection that sent them is entitled to that address. In any deployment
	// where a tenant configures its own IdP, that flag is set by the tenant's
	// administrator, so believing it is how an address gets squatted before its
	// owner ever signs in. A guard that cannot determine its answer refuses.
	//
	// Set [AllowAccountCreation] to keep the previous behavior, or supply a
	// policy that checks the asserted domain against the connection.
	CreatePolicy CreatePolicy

	// HTTPClient performs the token exchange and user-info request. Nil means
	// [DefaultHTTPClient]. Supply one to impose the egress policy the
	// deployment needs — this package does not restrict which addresses the
	// issuer may resolve to. See finding F-20.
	HTTPClient *http.Client

	// ClaimAllowlist names the raw ID-token claims copied into a newly created
	// user's Metadata. Empty means none: only the provider subject is stored.
	// Anything placed here is liable to end up in the application's own tokens
	// and in front of the browser, so name claims individually. See finding
	// F-21.
	ClaimAllowlist []string
}

// NewClient creates a new OIDC client.
//
// A nil Config.UserStore is accepted: the client then verifies assertions and
// reports claims without touching a user store.
func NewClient(cfg Config) (*Client, error) {
	if len(cfg.Providers) == 0 {
		return nil, errors.New("at least one provider is required")
	}
	if cfg.StateStore == nil {
		return nil, errors.New("state store is required")
	}

	providers := make(map[string]Provider, len(cfg.Providers))
	for i, p := range cfg.Providers {
		if p == nil {
			return nil, fmt.Errorf("provider at index %d is nil", i)
		}
		name := p.Name()
		if name == "" {
			return nil, fmt.Errorf("provider at index %d has an empty name", i)
		}
		// A duplicate name silently shadowed a provider before, so a callback
		// could be exchanged against a configuration the operator did not
		// intend. Fail at construction instead.
		if _, dup := providers[name]; dup {
			return nil, fmt.Errorf("provider %q is registered twice", name)
		}
		providers[name] = p
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = DefaultHTTPClient()
	}

	allowlist := make([]string, len(cfg.ClaimAllowlist))
	copy(allowlist, cfg.ClaimAllowlist)

	return &Client{
		providers:      providers,
		userStore:      cfg.UserStore,
		stateStore:     cfg.StateStore,
		redirectURL:    cfg.RedirectURL,
		linkPolicy:     cfg.LinkPolicy,
		createPolicy:   cfg.CreatePolicy,
		httpClient:     httpClient,
		claimAllowlist: allowlist,
	}, nil
}

// DefaultHTTPClient returns the HTTP client used when [Config].HTTPClient is
// nil: a client with [DefaultHTTPTimeout] and a transport that refuses a
// response body larger than [DefaultMaxResponseBytes].
//
// It does not restrict the addresses a request may reach. A deployment where
// the issuer URL is operator-supplied must supply its own client with a dialer
// that refuses link-local, loopback and private ranges, or the issuer URL is a
// server-side request forgery primitive against the internal network
// (finding F-20, CWE-918).
func DefaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   DefaultHTTPTimeout,
		Transport: &limitedTransport{max: DefaultMaxResponseBytes},
	}
}

// AuthURLOptions configures the authorization URL generation.
type AuthURLOptions struct {
	Provider    string
	RedirectURL string                 // Optional: overrides default redirect URL
	Scopes      []string               // Optional: overrides provider default scopes
	Metadata    map[string]interface{} // Optional: additional state data
}

// AuthorizationRequest is everything the caller must act on to start a flow
// safely: the URL to redirect the user agent to, the state parameter embedded
// in it, and the browser-binding value to store in a cookie.
type AuthorizationRequest struct {
	// URL is the provider's authorization endpoint with state, PKCE challenge
	// and, for an OIDC provider, a nonce already applied.
	URL string

	// State is the state parameter carried in URL. It is returned so the caller
	// can correlate or log the flow; it is not a secret the browser must hold.
	State string

	// Binding is the browser-binding value. Store it in a cookie — see
	// [BindingCookieName] for the attributes that make it useful — and present
	// it to [Client.HandleCallbackWithBinding]. Only its digest is persisted
	// server-side, so it cannot be recovered from the state store.
	Binding string
}

// GetAuthorizationURL generates an OAuth2/OIDC authorization URL.
//
// The returned flow carries state, PKCE and a nonce, but no browser binding:
// this signature has no way to hand the binding value back to the caller, so
// the callback cannot prove it reached the user agent that started the flow.
//
// Deprecated: use [Client.GetAuthorizationURLWithBinding] with
// [Client.HandleCallbackWithBinding]. A flow started here is not protected
// against the login CSRF of finding F-16 (CWE-352) and cannot be: the return
// type has nowhere to put the binding value the browser must hold. This entry
// point is kept only so existing callers keep compiling while they migrate.
func (c *Client) GetAuthorizationURL(ctx context.Context, opts AuthURLOptions) (string, error) {
	req, err := c.authorize(ctx, opts, false)
	if err != nil {
		return "", err
	}
	return req.URL, nil
}

// GetAuthorizationURLWithBinding generates an authorization URL and a
// browser-binding value that [Client.HandleCallbackWithBinding] requires.
//
// The binding closes login CSRF (finding F-16, CWE-352): an attacker who
// completes authentication against their own account and then induces a victim
// to visit the resulting callback URL fails, because the victim's browser does
// not hold the binding cookie issued when the flow started.
func (c *Client) GetAuthorizationURLWithBinding(ctx context.Context, opts AuthURLOptions) (*AuthorizationRequest, error) {
	return c.authorize(ctx, opts, true)
}

func (c *Client) authorize(ctx context.Context, opts AuthURLOptions, bind bool) (*AuthorizationRequest, error) {
	provider, exists := c.providers[opts.Provider]
	if !exists {
		return nil, ErrProviderNotFound
	}

	oauth2Config := provider.GetOAuth2Config()
	if oauth2Config == nil {
		return nil, fmt.Errorf("provider %q has no OAuth2 config: %w", opts.Provider, ErrProviderMisconfigured)
	}

	metadata, err := reserveStateMetadata(opts.Metadata)
	if err != nil {
		return nil, err
	}

	state, err := randomValue(stateEntropyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	redirectURL := opts.RedirectURL
	if redirectURL == "" {
		redirectURL = c.redirectURL
	}

	stateData := &storage.OIDCState{
		RedirectURL: redirectURL,
		Provider:    opts.Provider,
		Metadata:    metadata,
	}

	// F-17: RFC 9700 section 2.1.1 requires PKCE for every authorization-code
	// client, confidential ones included. The verifier never leaves this
	// process except into the state store; only the S256 challenge is sent.
	//
	// Here and below, each control is written to its typed field AND to the
	// metadata key that mirrors it. The typed field is where a store built
	// against the current documentation keeps it; the metadata key is where a
	// store built against v1.1.1, which has no column for a field that did not
	// exist then, still keeps it. Writing one and not the other leaves the
	// control at the mercy of which release the store was written for.
	verifier := oauth2.GenerateVerifier()
	stateData.CodeVerifier = verifier
	metadata[StateMetadataKeyPKCEVerifier] = verifier
	authOpts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier)}

	// F-16: an unbound flow records StateBindingUnbound rather than nothing, so
	// the callback can tell a flow that never had a binding from a record that
	// lost one.
	var binding string
	bindingRecord := StateBindingUnbound
	if bind {
		binding, err = randomValue(bindingEntropyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to generate state binding: %w", err)
		}
		bindingRecord = digest(binding)
	}
	stateData.BindingHash = bindingRecord
	metadata[StateMetadataKeyBinding] = bindingRecord

	// F-18: a nonce is only verifiable where an ID token will be verified. An
	// OAuth2-only provider issues none, and demanding a nonce claim from a
	// user-info response would fail every such flow, so the parameter is sent
	// exactly when the assertion can carry it back. Which of the two it was is
	// re-derived at callback time from the provider itself, not from the record.
	if provider.GetOIDCProvider() != nil {
		nonce, err := randomValue(nonceEntropyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to generate nonce: %w", err)
		}
		stateData.Nonce = nonce
		metadata[StateMetadataKeyNonce] = nonce
		authOpts = append(authOpts, oidc.Nonce(nonce))
	}

	if err := c.stateStore.StoreState(ctx, state, stateData, DefaultStateTTL); err != nil {
		return nil, fmt.Errorf("failed to store state: %w", err)
	}

	// The URL is built once, after the scope override is applied. Copying the
	// provider's config keeps the endpoint, client ID and redirect URI intact
	// and keeps the override out of the provider's own struct, which is shared
	// by every concurrent flow.
	authConfig := *oauth2Config
	if len(opts.Scopes) > 0 {
		authConfig.Scopes = opts.Scopes
	}

	return &AuthorizationRequest{
		URL:     authConfig.AuthCodeURL(state, authOpts...),
		State:   state,
		Binding: binding,
	}, nil
}

// CallbackResult represents the result of an OAuth2 callback.
type CallbackResult struct {
	// User is the account resolved or created from the assertion. It is nil
	// when [Config].UserStore is nil.
	//
	// Deprecated: identity is the application's to own. v2 removes user
	// creation and lookup from this package; resolve the identity yourself
	// from UserInfo.
	User *storage.User

	// UserInfo is what the provider asserted, after every control this package
	// applies has passed. It is the field that survives into v2.
	UserInfo *UserInfo

	// IsNewUser reports whether User was created by this callback.
	//
	// Deprecated: see User. v2 removes user creation from this package.
	IsNewUser bool

	RedirectURL string

	// Metadata is the caller's own state metadata from [AuthURLOptions],
	// with the library's reserved keys removed.
	Metadata map[string]interface{}
}

// HandleCallback processes the OAuth2 callback and returns user information.
//
// It fails with [ErrMissingBinding] when the flow was started by
// [Client.GetAuthorizationURLWithBinding], because the binding value cannot be
// presented through this signature.
//
// Deprecated: use [Client.HandleCallbackWithBinding]. This signature has no
// parameter for the binding cookie, so a flow completed here is only as strong
// as the entry point that started it — and [Client.GetAuthorizationURL], the
// one that can start such a flow, leaves finding F-16 open.
func (c *Client) HandleCallback(ctx context.Context, state, code string) (*CallbackResult, error) {
	return c.handleCallback(ctx, state, code, "")
}

// HandleCallbackWithBinding processes the OAuth2 callback and verifies, in
// constant time, that binding is the value issued when the flow started
// (finding F-16).
//
// binding is the cookie value the browser presented; an empty string means the
// browser presented none, which is a failure for a bound flow.
func (c *Client) HandleCallbackWithBinding(ctx context.Context, state, code, binding string) (*CallbackResult, error) {
	return c.handleCallback(ctx, state, code, binding)
}

func (c *Client) handleCallback(ctx context.Context, state, code, binding string) (*CallbackResult, error) {
	if state == "" || code == "" {
		return nil, ErrInvalidState
	}

	// GetState is documented as one-time use, so every control below runs
	// against a record that can no longer be replayed.
	stateData, err := c.stateStore.GetState(ctx, state)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) || errors.Is(err, storage.ErrExpired) {
			return nil, ErrInvalidState
		}
		return nil, fmt.Errorf("failed to get state: %w", err)
	}
	if stateData == nil {
		return nil, ErrInvalidState
	}

	// The provider is resolved before the controls are interpreted because it
	// is what says whether this flow requested a nonce at all. Nothing outside
	// this process happens until every control below has passed: the
	// authorization code is not redeemed by a callback that fails one.
	provider, exists := c.providers[stateData.Provider]
	if !exists {
		return nil, ErrProviderNotFound
	}

	oauth2Config := provider.GetOAuth2Config()
	if oauth2Config == nil {
		return nil, fmt.Errorf("provider %q has no OAuth2 config: %w", stateData.Provider, ErrProviderMisconfigured)
	}

	controls, err := readStateControls(stateData, provider.GetOIDCProvider() != nil)
	if err != nil {
		return nil, err
	}

	if bindingErr := verifyBinding(controls.binding, binding); bindingErr != nil {
		return nil, bindingErr
	}

	exchangeOpts := []oauth2.AuthCodeOption{oauth2.VerifierOption(controls.verifier)}

	// F-20: both the exchange below and the provider's user-info or JWKS
	// traffic read the client from the context, so this is the one place that
	// has to be right.
	ctx = oidc.ClientContext(ctx, c.httpClient)

	token, err := oauth2Config.Exchange(ctx, code, exchangeOpts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrExchangeFailed, err)
	}

	userInfo, err := provider.ExtractUserInfo(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUserInfoFailed, err)
	}
	if userInfo == nil {
		return nil, fmt.Errorf("provider %q returned no user info: %w", stateData.Provider, ErrUserInfoFailed)
	}

	userInfo.Provider = stateData.Provider

	if nonceErr := verifyNonce(controls.nonce, userInfo.RawClaims); nonceErr != nil {
		return nil, nonceErr
	}

	// F-01: sub is REQUIRED by OIDC Core section 2 and is the only identifier
	// an assertion carries that the provider guarantees not to reassign. An
	// assertion without one cannot name an identity, whether or not this
	// client resolves users.
	if userInfo.Subject == "" {
		return nil, ErrMissingSubject
	}

	result := &CallbackResult{
		UserInfo:    userInfo,
		RedirectURL: stateData.RedirectURL,
		Metadata:    callerMetadata(stateData.Metadata),
	}

	if c.userStore == nil {
		return result, nil
	}

	user, isNewUser, err := c.findOrCreateUser(ctx, userInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to find or create user: %w", err)
	}
	result.User = user
	result.IsNewUser = isNewUser

	return result, nil
}

// GetProvider returns a registered provider by name.
func (c *Client) GetProvider(name string) (Provider, error) {
	provider, exists := c.providers[name]
	if !exists {
		return nil, ErrProviderNotFound
	}
	return provider, nil
}

// ListProviders returns all registered provider names.
func (c *Client) ListProviders() []string {
	names := make([]string, 0, len(c.providers))
	for name := range c.providers {
		names = append(names, name)
	}
	return names
}

// findOrCreateUser resolves the assertion to an existing account or creates one.
//
// It refuses far more than it used to. An unverified or absent email address is
// refused outright, because this path is keyed on the email address and a claim
// the provider has not verified is a claim the provider's administrator can
// choose (CVE-2023-28131, RFC 9700 section 4). An existing account is adopted
// only when it was created by this same provider and already carries this
// subject identifier, or carries none yet and is pinned to this one on the way
// through; anything else needs [Config.LinkPolicy] to say so. An assertion that
// matches no account provisions one only where [Config.CreatePolicy] allows it,
// which by default is nowhere.
//
// Deprecated: creating and owning user records is the application's job, not a
// library's — only the application knows its tenancy and provisioning rules. v2
// removes this path entirely: HandleCallback will return verified claims and
// nothing else. Leave [Config].UserStore nil and resolve identity from
// [CallbackResult].UserInfo.
func (c *Client) findOrCreateUser(ctx context.Context, userInfo *UserInfo) (*storage.User, bool, error) {
	if userInfo.Subject == "" {
		return nil, false, ErrMissingSubject
	}
	if userInfo.Email == "" {
		return nil, false, ErrMissingEmail
	}
	if !userInfo.EmailVerified {
		return nil, false, ErrEmailNotVerified
	}

	existing, err := c.userStore.GetUserByEmail(ctx, userInfo.Email)
	switch {
	case err == nil:
		adopted, adoptErr := c.adopt(ctx, existing, userInfo)
		if adoptErr != nil {
			return nil, false, adoptErr
		}
		return adopted, false, nil
	case errors.Is(err, storage.ErrNotFound):
		// Fall through to creation.
	default:
		return nil, false, fmt.Errorf("failed to query user: %w", err)
	}

	if createErr := c.authorizeCreation(ctx, userInfo); createErr != nil {
		return nil, false, createErr
	}

	userID, err := generateUserID()
	if err != nil {
		return nil, false, fmt.Errorf("failed to generate user ID: %w", err)
	}

	user := &storage.User{
		ID:            userID,
		Email:         userInfo.Email,
		EmailVerified: true,
		Username:      userInfo.Username,
		Name:          userInfo.Name,
		Provider:      userInfo.Provider,
		// The subject is recorded in both places for the same reason the state
		// controls are: a store with no column for one of them must still have
		// the other, or the next sign-in has nothing to compare against and the
		// account becomes unreachable to the very identity that created it.
		ProviderSubject: userInfo.Subject,
		Metadata:        c.userMetadata(userInfo),
	}

	if err := c.userStore.CreateUser(ctx, user); err != nil {
		return nil, false, fmt.Errorf("failed to create user: %w", err)
	}

	return user, true, nil
}

// authorizeCreation asks [Config.CreatePolicy] whether a verified assertion
// that matches no account may provision one (finding F-01).
//
// A nil policy refuses. Every other control in this package answers a question
// about the flow; this one answers a question about the deployment — whether
// the connection that just authenticated is entitled to the address it
// asserted — and the library has no way to know it.
func (c *Client) authorizeCreation(ctx context.Context, userInfo *UserInfo) error {
	if c.createPolicy == nil {
		return fmt.Errorf("no Config.CreatePolicy is set: %w", ErrAccountCreationRefused)
	}

	allowed, err := c.createPolicy(ctx, userInfo)
	if err != nil {
		return fmt.Errorf("create policy: %w", err)
	}
	if !allowed {
		return ErrAccountCreationRefused
	}
	return nil
}

// adopt decides whether an assertion may be attached to an account that already
// exists for the same email address.
func (c *Client) adopt(ctx context.Context, existing *storage.User, userInfo *UserInfo) (*storage.User, error) {
	if existing == nil {
		return nil, fmt.Errorf("user store returned a nil user for a known email address: %w", ErrAccountLinkRequired)
	}

	recorded, err := recordedProviderSubject(existing)
	if err != nil {
		return nil, err
	}

	// Both comparisons are plain equality. A connection name and a subject
	// identifier are public — the subject travels in the ID token the browser
	// just presented, and both end up in logs — so there is no secret for a
	// timing oracle to recover. Constant-time comparison is reserved in this
	// package for the browser binding and the nonce, and using it here, on the
	// far side of a branch that has already tested the provider name, would
	// advertise a protection that is not being provided.
	sameProvider := existing.Provider != "" && existing.Provider == userInfo.Provider

	// The recorded != "" guard is not redundant with the case below it: without
	// it, an assertion that somehow reached here with no subject would match an
	// account that has none and adopt it on the strength of two empty strings.
	// The callback rejects an empty subject long before this, and this is what
	// keeps that true if it ever stops being.
	switch {
	case sameProvider && recorded != "" && recorded == userInfo.Subject:
		return existing, nil
	case sameProvider && recorded == "":
		return c.adoptUnrecorded(ctx, existing, userInfo)
	}

	if c.linkPolicy == nil {
		return nil, ErrAccountLinkRequired
	}

	allowed, err := c.linkPolicy(ctx, existing, userInfo)
	if err != nil {
		return nil, fmt.Errorf("link policy: %w", err)
	}
	if !allowed {
		return nil, ErrAccountLinkRequired
	}
	return existing, nil
}

// adoptUnrecorded adopts an account created by this same connection before this
// package recorded subject identifiers at all, and records the subject on it.
//
// Without this, every account any earlier release created is locked out for
// good: those records carry a provider name and no subject, the subject check
// can never match, and their owners meet [ErrAccountLinkRequired] on every
// sign-in with no way to clear it. The account was provisioned by this same
// registered connection, so adopting it grants that connection nothing it did
// not already have — but it IS trust on first use, and it lasts exactly one
// sign-in: from the backfill onwards the account is pinned to a subject and a
// different one is refused. An application that wants to police even that
// single step supplies [Config.LinkPolicy], which is consulted here.
//
// A failed write is fatal to the callback. Adopting anyway would leave the
// account permanently unpinned, quietly downgrading every future sign-in to the
// provider-name check this exists to escape.
func (c *Client) adoptUnrecorded(ctx context.Context, existing *storage.User, userInfo *UserInfo) (*storage.User, error) {
	if c.linkPolicy != nil {
		allowed, err := c.linkPolicy(ctx, existing, userInfo)
		if err != nil {
			return nil, fmt.Errorf("link policy: %w", err)
		}
		if !allowed {
			return nil, ErrAccountLinkRequired
		}
	}

	existing.ProviderSubject = userInfo.Subject
	if existing.Metadata == nil {
		existing.Metadata = make(map[string]interface{}, 1)
	}
	existing.Metadata[UserMetadataKeyProviderSubject] = userInfo.Subject

	if err := c.userStore.UpdateUser(ctx, existing); err != nil {
		return nil, fmt.Errorf("failed to record the provider subject on an existing account: %w", err)
	}
	return existing, nil
}

// userMetadata builds the metadata stored on a newly created user.
//
// F-01/F-21: the subject identifier is stored here as well as in
// [storage.User].ProviderSubject because a later assertion is checked against
// it, and a store that keeps only one of the two must still have that one.
// Nothing else is stored unless the application named it in
// [Config].ClaimAllowlist — the previous behavior copied the entire raw claim
// set, which then traveled into the application's own JWT and out to the
// browser, base64-decodable by anyone who saw it.
func (c *Client) userMetadata(userInfo *UserInfo) map[string]interface{} {
	metadata := make(map[string]interface{}, len(c.claimAllowlist)+1)
	for _, key := range c.claimAllowlist {
		if value, ok := userInfo.RawClaims[key]; ok {
			metadata[key] = value
		}
	}
	// Written last so an allow-listed claim named provider_sub cannot displace
	// the value the adoption check depends on.
	metadata[UserMetadataKeyProviderSubject] = userInfo.Subject
	return metadata
}

// recordedProviderSubject returns the subject identifier an account was last
// seen with, from [storage.User].ProviderSubject first and the metadata copy
// second.
//
// An empty return means the account never had one recorded, which the caller
// may backfill. A value that is present but unusable — the wrong type after a
// JSON round trip, or an empty string where a subject should be — is NOT that:
// it is a record that was written and then damaged, and reading it as "never
// recorded" would hand the account to whichever assertion arrives next. Those
// fail closed.
func recordedProviderSubject(user *storage.User) (string, error) {
	if user.ProviderSubject != "" {
		return user.ProviderSubject, nil
	}

	raw, ok := user.Metadata[UserMetadataKeyProviderSubject]
	if !ok {
		return "", nil
	}

	subject, ok := raw.(string)
	if !ok || subject == "" {
		return "", fmt.Errorf("recorded provider subject is %T, want a non-empty string: %w",
			raw, ErrAccountLinkRequired)
	}
	return subject, nil
}

// stateControls holds the per-flow controls recovered from a state record.
type stateControls struct {
	verifier string // PKCE code verifier (finding F-17)
	binding  string // browser-binding digest, or StateBindingUnbound (finding F-16)
	nonce    string // the nonce an OIDC provider must echo (finding F-18)
}

// readStateControls recovers the three controls this package wrote when the
// flow started, and refuses a record that lost any of them.
//
// wantNonce reports whether the provider this flow ran against issues ID
// tokens, which is the only trustworthy witness of whether a nonce was
// requested: it comes from the registered provider rather than from the record
// under examination, so a store that dropped the nonce cannot also erase the
// evidence that there was one.
//
// The verifier and the binding marker are written on EVERY flow, so their
// absence needs no witness at all — it can only mean the record did not survive
// the round trip. Refusing here costs a caller mid-flow across a deploy from a
// release that wrote neither location one failed sign-in inside the ten-minute
// state TTL. Accepting would cost every caller the control itself.
func readStateControls(state *storage.OIDCState, wantNonce bool) (stateControls, error) {
	verifier, err := readStateControl(state.CodeVerifier, state.Metadata, StateMetadataKeyPKCEVerifier)
	if err != nil {
		return stateControls{}, err
	}
	if verifier == "" {
		return stateControls{}, fmt.Errorf("no PKCE code verifier: %w", ErrStateControlMissing)
	}

	binding, err := readStateControl(state.BindingHash, state.Metadata, StateMetadataKeyBinding)
	if err != nil {
		return stateControls{}, err
	}
	if binding == "" {
		return stateControls{}, fmt.Errorf("no browser-binding marker: %w", ErrStateControlMissing)
	}

	nonce, err := readStateControl(state.Nonce, state.Metadata, StateMetadataKeyNonce)
	if err != nil {
		return stateControls{}, err
	}
	if wantNonce && nonce == "" {
		return stateControls{}, fmt.Errorf("no nonce for an OIDC flow: %w", ErrStateControlMissing)
	}

	return stateControls{verifier: verifier, binding: binding, nonce: nonce}, nil
}

// readStateControl reads one control from the typed field this package writes
// it to, falling back to the metadata key that mirrors it.
//
// Both copies come from one variable in one call, so two different non-empty
// values cannot be something this package produced: the record was rewritten,
// merged, or written by another library, and reading either half of a
// contradiction is guessing. It is reported as corruption instead.
func readStateControl(typed string, metadata map[string]interface{}, key string) (string, error) {
	mirrored, err := metadataString(metadata, key)
	if err != nil {
		return "", err
	}
	switch {
	case typed == "":
		return mirrored, nil
	case mirrored == "" || mirrored == typed:
		return typed, nil
	default:
		return "", fmt.Errorf("state control %q disagrees with its typed field: %w", key, ErrCorruptState)
	}
}

// verifyBinding compares the presented browser-binding value against the digest
// recorded when the flow started (finding F-16).
//
// recorded is never empty: readStateControls has already refused a record that
// carries no marker, so the only way to reach the "this flow had no binding"
// branch is for the flow to have said so at authorization time. That is what
// keeps the two entry points able to coexist during a migration without the
// unbound one becoming a way to strip the control off a bound flow.
//
// The comparison is constant-time because the value being compared is a secret:
// the browser holds it, the state store holds only its digest, and an attacker
// who could recover it byte by byte from a timing difference would hold
// everything the control asks for.
func verifyBinding(recorded, presented string) error {
	if recorded == StateBindingUnbound {
		return nil
	}
	if presented == "" {
		return ErrMissingBinding
	}
	if subtle.ConstantTimeCompare([]byte(digest(presented)), []byte(recorded)) != 1 {
		return ErrBindingMismatch
	}
	return nil
}

// verifyNonce checks the ID token's nonce claim against the value requested at
// authorization time (finding F-18).
//
// The claim is read from UserInfo.RawClaims rather than from the verified
// *oidc.IDToken because the Provider interface does not expose the token, and
// widening that interface would break every implementor. RawClaims is populated
// from the same verified token, so the value is as trustworthy as the
// signature check that produced it.
//
// An empty requested value here means an OAuth2-only flow, which issues no ID
// token to carry a nonce back: readStateControls has already refused an OIDC
// flow whose nonce went missing, so absence at this point is a fact about the
// provider and not about the record. The comparison is constant-time for the
// same reason as the binding: the requested nonce is an unguessable value held
// server-side, and the party supplying the other operand is the one this
// control exists to catch.
func verifyNonce(requested string, claims map[string]interface{}) error {
	if requested == "" {
		return nil
	}
	raw, ok := claims["nonce"]
	if !ok {
		return ErrMissingNonce
	}
	got, ok := raw.(string)
	if !ok || got == "" {
		return ErrMissingNonce
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(requested)) != 1 {
		return ErrNonceMismatch
	}
	return nil
}

// reserveStateMetadata copies the caller's metadata so the library's own keys
// are never written into a map the caller still holds, and refuses a caller key
// that would collide with them.
func reserveStateMetadata(src map[string]interface{}) (map[string]interface{}, error) {
	out := make(map[string]interface{}, len(src)+3)
	for key, value := range src {
		if strings.HasPrefix(key, StateMetadataPrefix) {
			return nil, fmt.Errorf("metadata key %q: %w", key, ErrReservedMetadataKey)
		}
		out[key] = value
	}
	return out, nil
}

// callerMetadata returns the caller's own metadata, without the library's
// reserved keys — the PKCE verifier in particular is not the application's to
// hold, log, or hand to a template.
func callerMetadata(src map[string]interface{}) map[string]interface{} {
	var out map[string]interface{}
	for key, value := range src {
		if strings.HasPrefix(key, StateMetadataPrefix) {
			continue
		}
		if out == nil {
			out = make(map[string]interface{}, len(src))
		}
		out[key] = value
	}
	return out
}

// metadataString reads a string the library itself wrote. A present value of
// the wrong type means the record was rewritten by something else, which is
// reported rather than read as absent.
func metadataString(metadata map[string]interface{}, key string) (string, error) {
	raw, ok := metadata[key]
	if !ok {
		return "", nil
	}
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("state metadata key %q is %T, want string: %w", key, raw, ErrCorruptState)
	}
	return value, nil
}

// digest returns the base64url-encoded SHA-256 of value. The browser-binding
// value is stored only as this digest, so a reader of the state store learns
// nothing replayable.
func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// randomValue returns n bytes from crypto/rand, base64url-encoded without
// padding.
func randomValue(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read %d random bytes: %w", n, err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// generateUserID generates a cryptographically secure user ID.
func generateUserID() (string, error) {
	return randomValue(16)
}

// limitedTransport caps every response body it returns, so a hostile or
// malfunctioning provider cannot exhaust memory through a response this
// package hands to a JSON decoder (finding F-20, CWE-400).
type limitedTransport struct {
	base http.RoundTripper
	max  int64
}

func (t *limitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	// One byte of headroom: a body of exactly max bytes must still reach EOF
	// rather than trip the limit.
	resp.Body = &limitedBody{inner: resp.Body, remaining: t.max + 1}
	return resp, nil
}

type limitedBody struct {
	inner     io.ReadCloser
	remaining int64
}

func (b *limitedBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		return 0, ErrResponseTooLarge
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.inner.Read(p)
	b.remaining -= int64(n)
	// remaining started one byte above the limit, so it only reaches zero once
	// a byte past the limit has been read. The check has to happen here rather
	// than on the next call: a body that delivers its last byte together with
	// io.EOF is never read again.
	if b.remaining <= 0 {
		return n, ErrResponseTooLarge
	}
	return n, err
}

func (b *limitedBody) Close() error {
	if err := b.inner.Close(); err != nil {
		return fmt.Errorf("close response body: %w", err)
	}
	return nil
}
