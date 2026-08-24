# Security Hardening Plan

Status: in progress (v1.x track)
Scope: the whole module, `v1.1.1` as the baseline.

This document is the register of every security defect found in an audit of
go-auth, the architectural decision that reshapes the library around them, and
the plan that closes them. It is written to be read by someone who has to
review the resulting diff.

---

## 1. The line

> **go-auth verifies credentials and emits verified facts. It never creates,
> mutates, or owns identity.**

Every critical finding below sits on the wrong side of that line, and that is
not a coincidence. `oidc.Client.findOrCreateUser` is an account-takeover vector
*because* it makes a policy decision — "an assertion carrying this email address
refers to this existing human" — that only the consuming application has the
context to make. `basic.Authenticator.Register` minting user IDs and writing
rows is the application's job, not a library's. The library reaching for
`storage.UserStore` in all four auth packages (`basic`, `jwt`, `oidc`,
`webauthn`) is the coupling that turned a set of primitives into a half-written
application.

The design consequence: cut the coupling and most of these defects stop being
things to defend against and start being things that cannot be expressed.

### 1.1 What is a primitive

A primitive is a mechanism nearly every Go backend needs and nearly none should
write itself, because writing it yourself is how you get it wrong:

| Primitive | Owns |
| --- | --- |
| password | hash, verify, strength policy, bcrypt-72 guard, constant-time dummy compare, rehash-on-cost-change |
| opaque token | mint high-entropy value, hash for storage, constant-time verify, TTL — one mechanism behind reset, verification, and invite tokens |
| jwt | mint and verify with pinned `alg`, `iss`, `aud`, and token type |
| session | ID generation, rotation, revocation, store abstraction |
| totp | enrol → confirm → validate with replay protection, hashed backup codes |
| webauthn | registration and assertion ceremonies with correct origin/RPID/sign-count handling |
| oidc relying party | authorization URL with state + nonce + PKCE; callback → **verified claims** |
| middleware | extract a credential, verify it, place a principal in context |
| audit | an event type and a logger interface |
| attempt limiter | a counter with a decay (v2) |

### 1.2 What is the application

User records. Identifier allocation. Tenancy. Just-in-time provisioning.
Account linking policy. Outbound email. RBAC. Organisation membership. What a
"principal" means in this product. None of these belong in a library that wants
to be dropped into an arbitrary Go service.

---

## 2. Threat model

Assumed adversaries, in the order they matter:

1. **An unauthenticated internet attacker** with the sign-in, registration,
   password-reset and OIDC callback endpoints, able to replay, truncate,
   reorder and forge anything not cryptographically bound.
2. **A malicious or compromised identity provider**, or a tenant administrator
   who legitimately controls their own IdP in a bring-your-own-connection
   deployment. This adversary can assert *any* claim set. This is the
   adversary that makes finding F-01 critical rather than theoretical.
3. **An attacker with read access to the credential store** — a SQL injection
   elsewhere in the host application, a leaked backup, a snapshot on shared
   storage. Anything the library persists in a directly-replayable form is a
   full compromise for this adversary.
4. **An authenticated user escalating** — replaying their own tokens outside
   the intended window or scope, rolling back a counter, reusing a one-time
   code.

Explicitly out of scope: physical access to the running process, a compromised
Go toolchain, and side channels below the level of a network-observable timing
difference.

---

## 3. Findings register

Severity is CVSS-flavoured judgement, not a computed score. "Proof" records how
the finding was established: `read` for source analysis, `exec` for a probe that
was actually run against the library.

### F-01 — OIDC identity is assigned from an unverified email claim

**Critical · CWE-287 · `auth/oidc/oidc.go` · proof: read**

`Client.findOrCreateUser` resolves the caller to an existing account with
`GetUserByEmail(ctx, userInfo.Email)` and returns that user. It never consults
`UserInfo.EmailVerified`, despite the field being populated two frames up in
`BaseOIDCProvider.ExtractUserInfo`. It never checks that the matched account was
originally created by the same provider, and it never compares the provider's
subject identifier against the one stored at first sight.

Any identity provider that can be induced to assert an arbitrary `email` claim —
which includes every provider in a bring-your-own-connection deployment, because
the tenant administrator configures it — takes over the matching account. This
is the class of defect published as CVE-2023-28131 ("nOAuth") and described in
RFC 9700 §4.
The library also has no notion of a tenant, so there is no boundary the takeover
would have to cross.

**Fix (v1):** refuse to link when the provider asserts `email_verified: false`;
require a non-empty `sub`; refuse to silently adopt an existing account whose
recorded `Provider` differs from the asserting provider, or whose stored
`provider_sub` differs from the asserted subject. Introduce an optional
`LinkPolicy` hook so an application that *wants* cross-provider linking must say
so in code. Deprecate the whole find-or-create path.

**Fix (v2):** `HandleCallback` returns verified claims. It does not touch a user
store, and `UserStore` leaves the package's dependencies.

### F-02 — A refresh token authenticates as an access token

**Critical · CWE-863 · `auth/jwt/jwt.go`, `middleware/jwt.go` · proof: exec**

`TokenManager.ValidateToken` never inspects `claims.Type`.
`JWTMiddleware.Middleware` calls exactly that function on the bearer token and,
on success, populates the request context and proceeds.

Executed against the library as shipped:

```
RESULT: refresh token ACCEPTED by ValidateToken, type="refresh" uid="u1"
        -> JWTMiddleware would authorize it
```

A refresh token defaults to a seven-day lifetime against an access token's
fifteen minutes. It is the credential most likely to be at rest in client
storage, and it is the one whose whole purpose is to be presented to exactly one
endpoint. Presenting it as a bearer token is accepted everywhere.

**Fix (v1):** pin the expected token type at validation, and give the middleware
an access-token-only entry point. Reject a refresh token presented as a bearer
credential.

### F-03 — Issuer and audience are minted but never verified

**Critical · CWE-347 · `auth/jwt/jwt.go` · proof: read**

`Config.Issuer` is written into `RegisteredClaims.Issuer` at mint time.
`ValidateToken` parses with a bare key function and asserts neither `iss` nor
`aud`. Two services that share a signing secret — the common case for a
deployment that rotates one secret through its environment — accept each other's
tokens. There is no audience concept at all.

**Fix (v1):** validate `iss` when configured, add an `Audience` config,
validate `aud`, and keep the existing signing-method pin. Do the same in
`RevokeRefreshToken`, which today parses with a key function that does not check
the signing method at all — inconsistent with `ValidateToken` even though the
current parser rejects the mismatched key type by accident rather than design.

### F-04 — RS256 and ES256 are documented but cannot work

**High · CWE-1188 · `auth/jwt/jwt.go` · proof: exec**

`Config.SigningKey` is `[]byte` and documented as "Secret key for HS256 or
private key for RS256". `generateToken` passes it to `token.SignedString`.
Asymmetric signing methods in `golang-jwt/v5` type-assert a `*rsa.PrivateKey` or
`*ecdsa.PrivateKey`. Executed:

```
RS256 GenerateAccessToken err = key is of invalid type: RSA sign expects *rsa.PrivateKey
RESULT: RS256 DOCUMENTED BUT BROKEN
```

The constructor accepts the configuration without complaint; the failure appears
at the first sign attempt, in production. A library that documents asymmetric
signing and cannot perform it pushes every consumer onto a shared symmetric
secret, which is the substrate for F-03.

**Fix (v1):** add `PrivateKey crypto.Signer` and `PublicKey crypto.PublicKey`
alongside the existing field, validate the key/method pairing in the constructor
so a misconfiguration fails at startup, and keep `SigningKey` working for HS\*.

### F-05 — Reset and email-verification tokens are stored in replayable form

**High · CWE-522 · `auth/basic/basic.go`, `storage/storage.go` · proof: read**

`StorePasswordResetToken(ctx, userID, token, expiresAt)` receives the same
string that is emailed to the user, and `ValidatePasswordResetToken(ctx, token)`
looks it up by that string. Whatever the implementor does, the library's
contract is "persist this bearer secret verbatim". The same holds for email
verification tokens. For threat-model adversary 3, a single read of that table
is account takeover across every user with a live token.

**Fix (v1):** hash the token inside the library before it reaches the store, and
hash again before lookup. The interface signature is untouched — implementors
keep compiling — and the only operational consequence is that tokens issued
before the upgrade stop validating, which for a one-hour reset TTL and a
24-hour verification TTL is a non-event.

### F-06 — TOTP secrets and backup codes are stored in plaintext

**High · CWE-522 · `auth/totp/totp.go`, `storage/storage.go` · proof: read**

`StoreTOTPSecret(ctx, userID, secret, backupCodes)` persists the shared secret
and every backup code as clear strings, and `GetTOTPSecret` reads them back out
to the caller. A store compromise yields a working second factor for every
enrolled user, which is precisely the property the second factor exists to deny.
Backup-code comparison is a plain `==` over the normalised strings, so it is
also not constant-time.

**Fix (v1):** an optional `Cipher` on the TOTP config that encrypts the secret
before it reaches the store and decrypts on read; backup codes hashed rather
than encrypted, since they only ever need to be compared; constant-time
comparison. All additive — a caller that supplies no cipher gets today's
behaviour with a documented warning.

### F-07 — TOTP enrolment activates before the user proves possession

**High · CWE-693 · `auth/totp/totp.go` · proof: read**

`GenerateSecret` calls `StoreTOTPSecret` unconditionally, so the factor is live
the instant the QR code is rendered. If the user never scans it, or scans it
into a device they then lose, they are locked out of their own account and the
library offers no path back that does not involve an administrator. Every
mainstream implementation requires the user to submit one valid code before the
factor is armed.

**Fix (v1):** a pending state and a `Confirm` step. `GenerateSecret` stores the
secret as pending; `Confirm(ctx, userID, code)` promotes it; `Validate` refuses
a pending secret. Additive methods, existing callers keep working via a
documented compatibility flag.

### F-08 — TOTP codes may be replayed inside their validity window

**High · CWE-294 · `auth/totp/totp.go` · proof: read**

`Manager.Validate` delegates to `pquerna/otp`, which is stateless by design.
RFC 6238 §5.2 is explicit that the verifier must not accept the same code twice.
An attacker who observes a code — shoulder-surfing, a phished form, a proxy —
has the remainder of the thirty-second step plus the skew window to reuse it.

**Fix (v1):** a `ReplayGuard` interface with an in-memory default, consulted
before a code is accepted, evicting at the same cadence the validator slides.

### F-09 — Sign-in leaks account existence through a timing side channel

**Medium · CWE-208 · `auth/basic/basic.go` · proof: read**

`Authenticate` returns `ErrInvalidCredentials` from the store-lookup branch
without performing a hash comparison. A known account costs one bcrypt
evaluation at cost 12; an unknown account costs a database round trip. The
difference is hundreds of milliseconds and is trivially measurable across the
internet. `GeneratePasswordResetToken` has the same shape, returning `("", nil)`
for an unknown user while a known user pays for token generation and a write.

**Fix (v1):** compare against a fixed dummy hash of the correct cost on the
not-found path, in both places.

### F-10 — Passwords longer than 72 bytes are silently truncated

**Medium · CWE-916 · `auth/basic/basic.go` · proof: read**

bcrypt ignores input past 72 bytes. `validatePassword` enforces a minimum of 8
and no maximum. A user with a 100-character passphrase is authenticated by its
first 72 bytes and has no way to know. Worse, a password manager generating long
strings with a common prefix produces colliding credentials.

**Fix (v1):** reject over-length passwords explicitly with a distinct sentinel
rather than silently truncating.

### F-11 — Registration is not atomic and swallows its own rollback failure

**Medium · CWE-460 · `auth/basic/basic.go` · proof: read**

`Register` creates the user, then stores the password hash. If the second step
fails it attempts `_ = a.userStore.DeleteUser(ctx, user.ID)` and discards the
result. When that cleanup also fails, the account exists with no credential: it
cannot be authenticated, and it blocks re-registration of the same address
through the duplicate check at the top of the function. The user is locked out
of their own email address with no self-service path.

**Fix (v1):** surface the rollback failure in the returned error so the caller
can act, and document that a store spanning both operations should implement
them transactionally.

### F-12 — A completed password reset leaves its token live

**Medium · CWE-613 · `auth/basic/basic.go` · proof: read**

`CompletePasswordReset` ends with:

```go
if err := a.credentialStore.DeletePasswordResetToken(ctx, token); err != nil {
    // Log error but don't fail the operation
    return nil
}
```

There is no logger in scope, so nothing is logged. The comment describes
behaviour the code does not implement, and the token stays valid until its TTL
expires — a second reset from the same link.

**Fix (v1):** return a wrapped error that identifies the password as changed but
the token as un-revoked, so the caller can decide. Never claim success silently.

### F-13 — Credential changes revoke nothing

**Medium · CWE-613 · `auth/basic`, `session`, `jwt` · proof: read**

`ChangePassword`, `ResetPassword` and `CompletePasswordReset` do not delete
sessions or revoke refresh tokens. The canonical reason a user changes a
password is that they believe it is compromised; after doing so, every session
the attacker holds continues to work for up to the session TTL and every refresh
token for up to seven days.

**Fix (v1):** `session.Manager.Rotate` for the fixation case, and documentation
naming the revocation the caller must perform.
**Fix (v2):** `SessionStore.DeleteAllForUser` — adding a method to a published
interface breaks every implementor, so it cannot land in v1.

### F-14 — Session identifiers are never rotated

**Medium · CWE-384 · `session/session.go` · proof: read**

A session ID is minted at creation and never changes. An attacker who fixes a
victim's session identifier before authentication retains it afterwards.

**Fix (v1):** `Rotate(ctx, oldID)` that mints a new identifier, moves the data,
and deletes the old entry.

### F-15 — HTTP Basic middleware runs bcrypt on every request

**Medium · CWE-400 · `middleware/basic.go` · proof: read**

`BasicAuthMiddleware.Middleware` calls `Authenticator.Authenticate` per request,
which is one cost-12 bcrypt evaluation — roughly 250 ms of CPU. A handful of
concurrent clients saturates a core. It also has no path to a second factor, so
mounting it anywhere silently creates an MFA bypass for that route.

**Fix (v1):** deprecate, and document that it must not be mounted on a route
reachable by an untrusted client.
**Fix (v2):** delete.

### F-16 — OIDC state is not bound to the browser that started the flow

**High · CWE-352 · `auth/oidc/oidc.go` · proof: read**

State is generated and stored server-side, then compared on callback. Nothing
ties it to the user agent that initiated the request. An attacker starts a flow,
obtains a valid `state`, completes authentication against their own account, and
induces the victim to visit the resulting callback URL. The victim's browser is
now authenticated as the attacker — login CSRF, the precondition for the class
of attacks where a victim's subsequent activity is recorded in an
attacker-controlled account.

**Fix (v1):** bind the state to a cookie value set at authorization time and
required at callback.

### F-17 — No PKCE

**High · CWE-319 · `auth/oidc/oidc.go` · proof: read**

`GetAuthorizationURL` calls `oauth2Config.AuthCodeURL(state)` with no challenge.
RFC 9700 §2.1.1 requires PKCE for authorization-code flows regardless of client
type. Without it, an authorization code intercepted in transit — a redirect
through a malicious app, a logged URL, a referer leak — is redeemable by whoever
holds it.

**Fix (v1):** generate an S256 verifier, carry it in `OIDCState` (a new field on
an existing struct, so additive), and supply it at exchange.

### F-18 — No nonce

**High · CWE-294 · `auth/oidc/oidc.go` · proof: read**

`storage.OIDCState` declares a `Nonce` field. Nothing ever writes it and nothing
ever reads it. The ID token's `nonce` claim is consequently unchecked, so a
token captured from one authentication can be replayed into another.

**Fix (v1):** generate, carry, and verify with a constant-time comparison.
Absence of the claim when one was requested is a hard failure.

### F-19 — `azp` is unchecked on multi-audience tokens

**Medium · CWE-287 · `provider/provider.go` · proof: read**

`BaseOIDCProvider.ExtractUserInfo` verifies the ID token through
`oidc.IDTokenVerifier`, which asserts that the configured client ID appears in
`aud`. OIDC Core §3.1.3.7 steps 4–5 require that when `aud` holds more than one
value, `azp` must be present and equal to the client ID. Without that check, a
token minted for a different relying party that merely lists us in a
multi-valued audience is accepted.

**Fix (v1):** enforce `azp` when `len(aud) > 1`.

### F-20 — Discovery and token exchange run on an unbounded default client

**Medium · CWE-918 · `auth/oidc`, `provider` · proof: read**

`oidc.NewProvider(ctx, issuerURL)` and `oauth2Config.Exchange(ctx, code)` use
`http.DefaultClient` unless a client is stashed in the context, which the
library never does. There is no timeout, no response size limit, and no
restriction on the address the issuer URL resolves to. In a deployment where the
issuer is operator-supplied — the entire premise of a
bring-your-own-connection product — this is a server-side request forgery
primitive against the internal network, and a memory exhaustion primitive
against a hostile response body.

**Fix (v1):** an `HTTPClient` config field threaded into the OIDC context, with
documentation of the required protections, plus a documented default timeout.
The library will not ship its own SSRF-safe dialer — that is infrastructure
policy, and it belongs to the application.

### F-21 — Identity provider claims are copied into the application's own JWT

**Medium · CWE-200 · `auth/jwt/jwt.go`, `auth/oidc/oidc.go` · proof: read**

`findOrCreateUser` stores the complete raw claim set under
`Metadata["raw_claims"]`, and `generateToken` copies `user.Metadata` wholesale
into the outgoing token's `Metadata` claim. Everything the IdP asserted —
group memberships, internal identifiers, whatever the directory happens to
release — is now in a token held by the browser, base64-decodable by anyone who
sees it, and counted against every subsequent request's header budget.

**Fix (v1):** stop copying metadata into tokens by default; require an explicit
allow-list of claim keys to include.

### F-22 — The audit wrapper cannot be kept correct

**Low · maintainability · `audit/wrapper.go` · proof: read**

652 lines mirroring nineteen methods across three types by hand. Any method
added to `basic.Authenticator`, `jwt.TokenManager` or `session.Manager` is
silently un-audited until someone remembers to write a matching wrapper. For a
package whose stated purpose is compliance evidence, "silently incomplete" is
the worst available failure mode.

**Fix (v2):** delete. `AuditLogger` and the event vocabulary are the primitive;
the application decorates its own call sites, where it also has the request
context the wrapper cannot see.

### F-23 — Untested code in the paths that matter most

**High · process · proof: exec**

Measured with `go test -race -covermode=atomic ./...`:

| package | statements covered |
| --- | --- |
| `auth/oidc` | **0.0 %** |
| `provider` | **0.0 %** |
| `auth/webauthn` | **0.0 %** |
| `middleware` | 31.2 % |
| `audit` | 56.3 % |
| `storage` | 76.1 % |
| `auth/totp` | 80.7 % |
| `auth/basic` | 82.6 % |
| `session` | 84.7 % |
| `auth/jwt` | 87.1 % |

The three packages at zero are the OIDC client, the eleven provider
configurations, and WebAuthn. There is also no `.golangci.yml`, so linting runs
on defaults: no `gosec`, no strict `errcheck`, no `bodyclose`, no `noctx`.
`govulncheck` is not in CI.

**Fix (v1):** the tooling and test programme in §5 and §6.

---

## 4. Release strategy

Go's module rules put any major version at or above 2 on a `/v2` import path, so
"a breaking change" and "a module path change" are the same event. The work is
therefore split by whether a fix can keep downstream code compiling.

**v1.x — every fix that preserves compilation.** Behaviour changes that close a
vulnerability ship here as `fix:`, because a change that removes an
exploitable behaviour is a bug fix, not a breaking change. Anything destined for
removal gets a `// Deprecated:` marker in the same release so `staticcheck`
warns downstream immediately.

**v2 — the re-architecture.** Removals, interface reshaping, and the controls
whose correct form only exists after the removals.

| Item | Lands | Why |
| --- | --- | --- |
| F-01 … F-21 fixes | v1.x | signature-preserving |
| Deprecation markers | v1.x | gives downstream a full release of warning |
| `session.Manager.Rotate` | v1.x | new method, additive |
| Secure-by-default constructor validation | v1.x | behaviour only |
| Remove `provider/*` vendor files | v2 | deletion |
| Remove `audit/wrapper.go` | v2 | deletion |
| `storage/memory.go` → `storagetest` | v2 | moves out of the public surface |
| Remove `middleware/basic.go` | v2 | deletion |
| Drop `UserStore` from library dependencies | v2 | changes four constructors |
| `SessionStore.DeleteAllForUser` | v2 | adding to a published interface breaks implementors |
| `attempt` limiter package | v2 | designed once, against the v2 shape |
| Per-tenant `ProviderResolver`, `JITPolicy` | v2 | not features — the residue of removing find-or-create |

Rate limiting and JIT gating are deliberately *not* in v1. Adding a `JITPolicy`
hook to a code path that v2 deletes outright is designing the same thing twice.

### 4.1 What v2 removes

The library is 5,749 lines excluding tests and examples.

| Removal | ~lines | Reason it is not a primitive |
| --- | --- | --- |
| `provider/*` vendor files | 900 | configuration, not logic; OIDC discovery already covers every OIDC-capable provider from an issuer URL alone. Zero coverage today. |
| `audit/wrapper.go` | 652 | see F-22 |
| `storage/memory.go` from the public API | 666 | ships an in-memory identity store as public API; becomes a conformance harness downstream implementors run against their own store |
| `middleware/basic.go` | 77 | see F-15 |
| OIDC user create/lookup | 60 | see F-01 |
| `basic` user CRUD | 80 | the library hashes and verifies; it does not own the row |

Roughly 2,400 lines — 42 % of the library, and the bulk of what is currently
untested.

---

## 5. Tooling

`.golangci.yml` does not exist, so the linter runs on defaults. The new
configuration enables, at minimum:

- `gosec` — the security-focused analyser, including weak randomness, unhandled
  crypto errors, and hardcoded credentials.
- `errcheck` in strict mode, with blank-identifier assignment disallowed. Every
  `_ =` in the current tree is a suppressed error, and two of them are findings
  above.
- `bodyclose`, `noctx`, `contextcheck` — leaked response bodies and requests
  issued without a context are how a library becomes a resource leak in
  somebody else's service.
- `errorlint`, `nilnil`, `exhaustive`, `copyloopvar`, `forbidigo` (banning
  `math/rand` outright and `time.Now` inside comparison paths).
- `depguard` — the dependency set is a stated design value, so it is enforced by
  rule rather than by discipline.
- `revive` configured against the Google Go style guide, `paralleltest`,
  `testifylint`.

CI additionally gains `govulncheck`, fuzz targets exercised on a short budget
per run, a per-package coverage floor that fails the build on regression, and a
build job for `examples/complete`, which has its own `go.mod` and can otherwise
rot silently when the API changes.

---

## 6. Test programme

The goal is not coverage percentage. It is that **each fix ships with a test
that fails when the fix is reverted**, and that each test names the attack it
defends against. A test that still passes with its fix removed is not evidence.

Adversarial suites, organised by the real defect classes they mirror:

**JWT** — `alg: none`; algorithm confusion (an HS256 token signed with the
RS256 public key); `kid` injection via path traversal; oversized-header denial
of service (the CVE-2025-30204 class); `aud` type confusion between string and
array (the GHSA-mh63-6h87-95cp class); `exp`/`nbf` boundary conditions; refresh
token presented as bearer (F-02); cross-issuer replay (F-03).

**OIDC** — unverified-email takeover (F-01, the CVE-2023-28131 class); identity
provider mix-up per RFC 9700 §4.4; authorization code injection; PKCE downgrade
and omission; nonce omission and replay; state fixation and login CSRF (F-16);
`azp` on multi-audience tokens (F-19); JWKS fetch against an internal address
and against a rebinding DNS answer (F-20); `redirect_uri` exact-match
enforcement.

**WebAuthn** — origin and RPID confusion; sign-counter rollback, the signal a
cloned authenticator produces; user-handle mismatch; challenge replay;
attestation-type downgrade; credential-ID collision across two users.

**TOTP** — code replay inside the window (F-08); skew boundary; backup-code
reuse; secret entropy; enrol-without-confirm lockout (F-07).

**Password** — 72-byte truncation (F-10); embedded NUL; account-existence timing
(F-09), measured statistically with a tolerance wide enough not to flake in CI
but tight enough to catch the removal of the dummy comparison.

**Session** — fixation across authentication (F-14); TTL boundary; revocation
completeness.

Fuzz targets cover every parser and decoder that touches untrusted input. A
`storagetest` conformance suite lets a downstream store implementation prove
itself against the contract rather than against its author's reading of a
doc comment.

---

## 7. Migration notes for consumers

Upgrading within v1.x requires no code changes. Three behaviour changes are
observable:

1. Password-reset and email-verification tokens issued before the upgrade stop
   validating, because they are now hashed at rest (F-05). The reset TTL is one
   hour and the verification TTL is 24 hours, so the window closes on its own.
2. `ValidateToken` rejects refresh tokens (F-02). Code that deliberately
   presented a refresh token as a bearer credential was exploiting the defect
   and must switch to `RefreshAccessToken`.
3. Tokens no longer carry `user.Metadata` unless the keys are explicitly
   allow-listed (F-21). A consumer reading claims out of the metadata map must
   opt in.

Deprecation warnings appear for every symbol v2 removes. Nothing is deleted in
v1.
