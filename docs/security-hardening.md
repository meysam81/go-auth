# Security Hardening Plan

Status: v1.x fixes landed on `harden/security-overhaul-v1`; one finding (F-29)
remains open by design and one (F-30) is an accepted risk. See §8.
Scope: the whole module, `v1.1.1` as the baseline.

This document is the register of every security defect found in go-auth — the
original audit of v1.1.1 (F-01 … F-23), what writing the missing WebAuthn tests
turned up (F-24 … F-29), and what two independent adversarial reviews found in
the fix work itself (F-30 … F-34) — together with the architectural decision
that reshapes the library around them and the plan that closes them. It is
written to be read by someone who has to review the resulting diff.

Sections 3 to 6 describe the code **as it stands**, not as it was planned. Where
the plan and the tree disagreed, the tree won and the sentence was corrected; §7
is the list of run-time behaviour changes a consumer upgrading within v1.x must
act on, and §8 records what is still open.

---

## 1. The line

> **go-auth verifies credentials and emits verified facts. It never creates,
> mutates, or owns identity.**

Every critical finding below sits on the wrong side of that line, and that is
not a coincidence. `oidc.Client.findOrCreateUser` is an account-takeover vector
_because_ it makes a policy decision — "an assertion carrying this email address
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

| Primitive          | Owns                                                                                                                               |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| password           | hash, verify, strength policy, bcrypt-72 guard, constant-time dummy compare, rehash-on-cost-change                                 |
| opaque token       | mint high-entropy value, hash for storage, constant-time verify, TTL — one mechanism behind reset, verification, and invite tokens |
| jwt                | mint and verify with pinned `alg`, `iss`, `aud`, and token type                                                                    |
| session            | ID generation, rotation, revocation, store abstraction                                                                             |
| totp               | enrol → confirm → validate with replay protection, hashed backup codes                                                             |
| webauthn           | registration and assertion ceremonies with correct origin/RPID/sign-count handling                                                 |
| oidc relying party | authorization URL with state + nonce + PKCE; callback → **verified claims**                                                        |
| middleware         | extract a credential, verify it, place a principal in context                                                                      |
| audit              | an event type and a logger interface                                                                                               |
| attempt limiter    | a counter with a decay (v2)                                                                                                        |

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
   deployment. This adversary can assert _any_ claim set. This is the
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

**Fix (v1), as shipped:** `HandleCallback` refuses an assertion carrying no
`sub`, whether or not a user store is configured. `findOrCreateUser`
additionally refuses an absent email address and one the provider marked
`email_verified: false`. An existing account is adopted only when its recorded
`Provider` equals the asserting provider _and_ its recorded subject equals the
asserted one; an account carrying no recorded subject is pinned to this one on
the way through (`adoptUnrecorded` — trust on first use, lasting exactly one
sign-in, and a failed write fails the callback rather than leaving the account
permanently unpinned). Anything else requires `Config.LinkPolicy` to say yes.

Provisioning is no longer implicit either: an assertion matching no account is
refused with `ErrAccountCreationRefused` unless `Config.CreatePolicy` authorises
it, and a nil policy refuses. `AllowAccountCreation` restores the previous
behaviour in one line for a deployment that wants it. See §7 item 2 — this is
the most consumer-visible change on the branch.

The whole find-or-create path, `Config.UserStore`, `CallbackResult.User` and
`CallbackResult.IsNewUser` carry `// Deprecated:` markers.

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

**Fix (v1), as shipped:** an optional `Config.Cipher` encrypts the shared secret
before it reaches the store and decrypts it on read; backup codes are stored as
a keyed SHA-256 digest — sealed with the `Cipher` when one is configured — and
compared in constant time.

The two halves differ in what an unconfigured `Cipher` means, and the original
sentence here ("a caller that supplies no cipher gets today's behaviour") was
true only of the secret:

- **The secret** is still written in the pre-hardening plaintext form when no
  `Cipher` is set _and_ `ActivateOnGenerate` is set — that combination keeps the
  stored column byte-identical, so the library can be rolled back. Every other
  combination writes the tagged payload described in the package doc comment,
  which is a new on-disk shape even without encryption, because the pending
  marker has nowhere else to live inside a frozen `CredentialStore` interface.
- **Backup codes are hashed unconditionally**, cipher or no cipher. There is no
  flag that restores plaintext codes and none is planned: they only ever need to
  be compared. The consequence is a signature-preserving but semantically
  breaking change to `CredentialStore.GetTOTPSecret`, which now returns digests
  where it used to return printable codes. See §7 item 5.

### F-07 — TOTP enrolment activates before the user proves possession

**High · CWE-693 · `auth/totp/totp.go` · proof: read**

`GenerateSecret` calls `StoreTOTPSecret` unconditionally, so the factor is live
the instant the QR code is rendered. If the user never scans it, or scans it
into a device they then lose, they are locked out of their own account and the
library offers no path back that does not involve an administrator. Every
mainstream implementation requires the user to submit one valid code before the
factor is armed.

**Fix (v1), as shipped:** a pending state and a `Confirm` step. `GenerateSecret`
stores the secret as pending; `Confirm(ctx, userID, code)` promotes it;
`Validate` and `ValidateBackupCode` return `ErrPendingConfirmation` for a
pending secret; `IsEnabled` reports false for one and the new `IsPending`
distinguishes "never enrolled" from "enrolled, not confirmed"; `Disable` cancels
a pending enrolment so a user can restart without an administrator.

**Existing callers do NOT keep working.** The compatibility flag
(`Config.ActivateOnGenerate`) defaults to _off_, because the safe default is the
one that cannot lock a user out, and an opt-out that has to be typed is the only
kind an upgrade cannot skip. A v1.1.1-era caller that renders a QR code and then
calls `Validate` therefore gets `ErrPendingConfirmation` until it either adds a
`Confirm` step or sets the flag. The earlier wording in this section — "existing
callers keep working via a documented compatibility flag" — described the flag
as if it were on. It is not, and the fix is right; the sentence was wrong. See
§7 item 3.

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

**Fix (v1), as shipped — OPT-IN, not on by default.** The binding lives on a new
pair of entry points, because the old pair has nowhere to put it:

| Start the flow                                                                 | Finish it                                              | F-16 closed? |
| ------------------------------------------------------------------------------ | ------------------------------------------------------ | ------------ |
| `GetAuthorizationURLWithBinding` → `AuthorizationRequest{URL, State, Binding}` | `HandleCallbackWithBinding(ctx, state, code, binding)` | yes          |
| `GetAuthorizationURL` → `string`                                               | `HandleCallback(ctx, state, code)`                     | **no**       |

`GetAuthorizationURL` returns a bare `string`, so there is no way to hand the
caller a value for the browser to hold; a flow started there records
`StateBindingUnbound` and remains exactly as exposed to login CSRF as v1.1.1
was. Both old entry points carry `// Deprecated:` markers naming the
replacement, and that marker is the whole of the protection an unchanged caller
receives. A caller must move to the bound pair and store `Binding` in a cookie —
`BindingCookieName` (`__Host-go-auth-oidc-binding`) documents the attributes —
to actually get the control.

What the two entry points cannot do is contaminate each other: a _bound_ flow
completed through `HandleCallback` fails with `ErrMissingBinding`, so the
unbound path is not a way to strip the binding off a flow that had one.

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

**Fix (v1), as shipped — stricter than the line above.**
`verifyAuthorizedParty` applies both halves of OIDC Core §3.1.3.7:

1. `azp` is **required** when `aud` names more than one party
   (`ErrMissingAuthorizedParty`), and
2. `azp` must equal the client ID **whenever it is present, at any audience
   count** (`ErrAuthorizedPartyMismatch`) — not only when `len(aud) > 1`.

The second rule is the one usually missed, and dropping it would let a provider
that emits `azp` on every token hand this client a token minted for somebody
else as long as `aud` held one value. A present-but-unusable `azp` (`null`, a
non-string, an empty string) is treated as missing rather than as absent, so a
multi-audience token cannot disarm rule 1 by emitting `azp: null`. The
comparison is constant-time, which costs nothing and keeps the shape uniform
with the other credential comparisons in the package.

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

| package         | statements covered |
| --------------- | ------------------ |
| `auth/oidc`     | **0.0 %**          |
| `provider`      | **0.0 %**          |
| `auth/webauthn` | **0.0 %**          |
| `middleware`    | 31.2 %             |
| `audit`         | 56.3 %             |
| `storage`       | 76.1 %             |
| `auth/totp`     | 80.7 %             |
| `auth/basic`    | 82.6 %             |
| `session`       | 84.7 %             |
| `auth/jwt`      | 87.1 %             |

The three packages at zero are the OIDC client, the eleven provider
configurations, and WebAuthn. There is also no `.golangci.yml`, so linting runs
on defaults: no `gosec`, no strict `errcheck`, no `bodyclose`, no `noctx`.
`govulncheck` is not in CI.

**Fix (v1):** the tooling and test programme in §5 and §6.

---

### F-24 … F-29 — what the WebAuthn suite found

F-23 recorded `auth/webauthn` at 0.0 % coverage. Writing the suite §6 asks for
is what surfaced the six findings below: none of them were visible from the
original read of the package, and the first one made every other one
unobservable. They are numbered here because this document claims to be the
register of every defect found, and a defect that only ever existed as a skipped
test is a defect nobody outside this branch can see.

### F-24 — A WebAuthn challenge expires 300 nanoseconds after it is issued

**High · CWE-613 · `auth/webauthn/webauthn.go` · proof: exec**

Both ceremonies stored the challenge with
`StoreState(ctx, sessionID, stateData, 300)` under a `// 5 min timeout` comment.
The parameter is a `time.Duration`, so the untyped constant `300` is 300
_nanoseconds_. Against any store that honours the TTL it is handed — including
`InMemoryOIDCStateStore` in this repository, which stamps
`expiresAt: time.Now().Add(ttl)` and returns `ErrExpired` afterwards — the
challenge lapsed before the options finished serialising, so no ceremony this
package started could ever be completed.

Nothing failed loudly because `auth/webauthn` had no tests at all: this is F-23
cashing out. Writing the suite required a state-store harness that floors every
TTL it is given, because no test could reach the ceremony logic until the 300 ns
was neutralised. Read the other way — a store that ignores a TTL it cannot
interpret — the same line gives the challenge the lifetime of the record
instead, so it is a total outage or an unbounded challenge window depending
entirely on whose store is plugged in. Neither is the five minutes the comment
claimed.

**Status: fixed.** `Config.Timeout` is now milliseconds with a five-minute
default, is refused above `maxCeremonyTimeout` (15 minutes) and below zero at
construction, and drives three deadlines from one number: the hint sent to the
browser, the expiry stamped inside the stored session record
(`Timeouts.*.Enforce: true`), and the TTL of the challenge record. The
relying-party-side expiry is what survives a store that drops the TTL.

### F-25 — A cloned authenticator is undetectable

**High · CWE-294 · `auth/webauthn/webauthn.go` · proof: exec**

`FinishLogin` copied `credential.Authenticator.SignCount` into the stored
credential and wrote it back. It never compared it against the value already on
record, so an assertion presenting a _lower_ counter authenticated and then
overwrote the higher value with it. The signature counter is the only signal
WebAuthn Level 3 §6.1.1 produces for a duplicated private key — origin, RP ID
hash, challenge and signature all verify perfectly for a clone — and the library
was discarding it.

**Status: fixed.** `isSignCountRollback` refuses a non-advancing counter with
`ErrCredentialCloned` (wrapping `ErrAuthenticationFailed`, so an existing caller
keeps refusing the sign-in unchanged while a caller that wants to raise a
security event can match the specific sentinel). An authenticator that reports 0
on both sides is treated as counterless rather than as a clone, which is the
case §6.1.1 explicitly exempts.

### F-26 — The counter write failure was printed to stdout and swallowed

**Medium · CWE-778 · `auth/webauthn/webauthn.go` · proof: read**

When the counter update failed, the library executed
`fmt.Printf("Warning: failed to update credential sign count: %v\n", err)` and
returned success. A library writing to the host process's stdout is a defect on
its own — it is not the application's log, it is not structured, and it cannot
be turned off — but the security consequence is F-25's: a dropped counter write
leaves the next assertion measured against a stale value, so the clone detector
is permanently blind for that credential and nothing anywhere records that it
happened.

**Status: fixed.** The write failure fails the ceremony with
`ErrSignCountNotPersisted`, which deliberately does _not_ wrap
`ErrAuthenticationFailed`: the credential proved itself, the relying party's own
storage is what failed, and the two deserve different alerts. No session is
issued either way. Nothing in the package writes to stdout.

### F-27 — WebAuthn ceremonies and OIDC flows share one state namespace

**Medium · CWE-843 · `auth/webauthn/webauthn.go` · proof: exec**

Challenges live in a `storage.OIDCStateStore`, the same store and the same key
space the OIDC flow uses. Both `Begin` calls wrote `Provider: "webauthn"` into
the record, and no read path ever checked it. Both flows hand their key to the
browser — the OIDC state in the authorization URL, the WebAuthn challenge in the
credential options — so either flow could be made to consume the other's
single-use record, with the confusion landing on whichever decoder ran next.

**Status: fixed.** `loadCeremony` requires the `webauthn` tag and refuses
anything else, alongside a structural check that the record carries both the
user ID and the session blob this package wrote. Every failure collapses into
one internal sentinel so a caller cannot tell a lapsed challenge from one that
never existed (CWE-204).

### F-28 — WebAuthn Level 3 backup flags were not persisted

**Medium · CWE-670 · `auth/webauthn/webauthn.go` · proof: exec**

`storage.WebAuthnCredential` has no field for the BE (backup eligible) and BS
(backup state) flags, and the registration path stored neither. WebAuthn Level 3
§7.2 requires an assertion whose backup eligibility disagrees with the value
recorded at registration to be refused — and a relying party that cannot
remember the registered value compares every assertion against a constant
`false`, which refuses every synced passkey, because those report BE=1.

**Status: fixed** without touching the frozen struct: the flags ride in the
credential's own extensible `Metadata` map under documented keys, and
`FuzzCredentialFlagMetadata` covers the round trip against hostile metadata.

### F-29 — `BeginLogin` distinguishes an unknown account from one with no passkey

**Medium · CWE-204 · `auth/webauthn/webauthn.go` · proof: exec · OPEN**

`BeginLogin` answers an unknown identifier with `ErrUserNotFound` and an
existing account that has enrolled no credential with `ErrCredentialNotFound`.
The endpoint is unauthenticated by nature — it is what a sign-in page calls
before anything is proven — so the pair is an account-existence oracle for
anyone willing to send identifiers at it.

**Status: OPEN. Not fixable under the v1 signature freeze**, and this is the
only remaining documented gap in the tree: it is the single surviving `gap()`
skip in `auth/webauthn/adversarial_test.go`.

Both sentinels are exported, are documented as the two answers this call gives,
and callers branch on them to choose between "no such account" and "add a
passkey". Collapsing them keeps the package compiling while silently changing
what every existing caller is told — a signature-preserving change that breaks
behaviour invisibly, which is exactly what §4 says v1 must not do. The real fix
is the one deployments use: return options over a fabricated allow-list so the
two cases are indistinguishable on the wire. That needs a stable source of decoy
credential IDs — a per-relying-party secret and the API to configure it —
neither of which exists in v1.

**Fix (v2):** one indistinguishable answer plus decoy allow-list entries derived
from a configured RP secret. The test is already written so that its assertion
branch is taken the moment the two errors become indistinguishable, at which
point it converts from a documented hole into a regression guard without being
rewritten.

---

### F-30 … F-34 — defects in the fix work itself

Everything below was introduced or left behind by this branch's own remediation
and found by the two independent adversarial reviews described in §8, not by the
original audit of v1.1.1. They are numbered for the same reason the WebAuthn
findings are: a register that only lists the defects that make the library look
bad in its old version is not a register.

### F-30 — `NewMicrosoftProvider` disables ID token issuer verification

**Medium · CWE-287 · `provider/microsoft.go` · proof: read · ACCEPTED**

The constructor now passes `skipIssuerCheck: true` to the underlying
`oidc.IDTokenVerifier`. The reasoning is correct and is stated in the code:
Microsoft's multi-tenant `common` endpoint publishes the literal issuer
`https://login.microsoftonline.com/{tenantid}/v2.0`, every ID token carries the
signing tenant's own GUID in `iss`, and there is therefore no fixed value to
pin. On `main` this mismatch made discovery fail outright, so the constructor
did not work at all.

It is recorded here because "we disabled issuer verification on a provider
constructor" is a sentence that belongs in a security register whatever its
justification. The consequence, stated plainly: **any Entra ID tenant on the
internet can mint a token this provider accepts.** The provider proves the
assertion came from Microsoft and was minted for the configured client ID; it
does not, and cannot, prove which organisation the user belongs to.

**Compensating control (the application's, not the library's):** read `tid` out
of `UserInfo.RawClaims` and check it against an allow-list before treating the
user as anybody. A single-tenant application should not call this constructor at
all — `NewOIDCProvider` with
`https://login.microsoftonline.com/<tenant-id>/v2.0` pins the issuer normally.
Both are in the constructor's doc comment, which is also marked
`// Deprecated:` along with every other vendor constructor.

### F-31 — A TOTP code could be replayed by adding a space to it

**High · CWE-294 · `auth/totp/totp.go` · proof: exec**

The F-08 replay guard was keyed on the code exactly as submitted, while
`hotp.ValidateCustom` compares the passcode after `strings.TrimSpace`. So
`"170225"` and `" 170225"` were one code to the validator and two different keys
to the guard — and `strings.TrimSpace` cuts every Unicode space character in any
combination at either end, so one accepted code had an unbounded set of guard
keys. Every one of them validated, while the guard sincerely believed it had
never seen the code. The fix for F-08 was, in practice, bypassable by pressing
the space bar.

**Status: fixed.** `normalizeSubmittedCode` folds a submission exactly the way
the validator folds it, and `recordCode` is the single place a guard key is
built, so `Validate` and `Confirm` cannot drift apart. The rule is deliberately
`strings.TrimSpace` and not a stricter normalisation of our own invention: a
normalisation that disagreed with the validator about one character would reopen
the same gap.

### F-32 — A store that drops a control silently disarmed it

**High · CWE-807 · `auth/oidc/oidc.go` · proof: exec**

PKCE (F-17), the browser binding (F-16) and the nonce (F-18) were added as new
fields on `storage.OIDCState`. A v1.1.1-era store implementation maps the
columns it knows about and reconstructs the struct from them, so those fields
came back empty — and an empty control read as "this flow had no such control".
The record looked valid, every conformance test passed, and PKCE, the binding
and the nonce became decoration. This is the fail-open shape §1's threat model
exists to prevent: a control an attacker can remove by deleting a column.

**Status: fixed.** Each control is written to both its typed field and a
mirrored reserved key in `Metadata`; `readStateControls` refuses a record that
carries neither copy with `ErrStateControlMissing`, and refuses two copies that
disagree with `ErrCorruptState`. "Deliberately unbound" is recorded as the
explicit marker `StateBindingUnbound` rather than as an empty field, so it
cannot be confused with a dropped one. The cost is one failed sign-in for a
caller mid-flow across the deploy, inside the ten-minute state TTL.

### F-33 — The TOTP payload tag was outside everything that authenticated it

**High · CWE-345 · `auth/totp/totp.go` · proof: exec**

The F-06/F-07 payload carries the pending marker and the ciphertext
discriminator in a prefix — `$gat1$<state>$<encoding>$<data>` — and the prefix
has to sit outside the ciphertext, because `IsEnabled` must answer without key
material. That left it writable by anyone who could write to the store:
rewriting `$gat1$a$e$…` to `$gat1$a$r$<attacker secret>` downgraded a sealed
secret to a plaintext one of the attacker's choosing, and flipping `p` to `a`
armed a factor the user never confirmed.

**Status: fixed.** Encoding `e` seals a copy of the tag _and_ a digest of the
user ID inside the authenticated plaintext, and both are checked after
decryption (`ErrSecretTampered`). The user ID is in there because the markers
alone cannot stop a store writer from enrolling a factor of their own and
copying that perfectly genuine row onto someone else's account. A configured
`Cipher` also refuses to read an unencrypted secret at all, with
`Config.AllowLegacyPlaintextSecrets` as the documented, deprecated one-way
migration window.

### F-34 — Every successful token revocation was audited anonymously

**Low · CWE-778 · `audit/wrapper.go` · proof: exec**

`TokenManagerWrapper.RefreshAccessToken` and `.RevokeRefreshToken` resolved the
event's actor by calling `ValidateToken` on the refresh token. After F-02,
`ValidateToken` means `ValidateAccessToken` and rejects every refresh token on
its type claim — so the lookup could never succeed, the actor was silently
dropped, and each successful `token.refresh` and `token.revoke` event was
written with nobody's name on it. A fix in one package blinded a control in
another, and the "best effort" comment made the silence look intentional.

**Status: fixed.** Both sites call `ValidateRefreshToken`. `RevokeRefreshToken`
resolves the actor _before_ revoking, because afterwards the lookup fails by
design. A lookup that still fails is written to the event's metadata by
`noteActorLookupError` rather than dropped, so "no actor" and "actor could not
be resolved" are distinguishable in the log — and it goes to metadata, not to
`Error`, because failing to enrich an event does not make the operation it
records a failure.

### F-35 — A half-wired Authenticator let the password alone pass MFA

**Critical · CWE-306 · `auth/basic/basic.go` · proof: exec · shipped in v1.1.2**

`IsTOTPEnabled` and `IsTOTPPending` answered `(false, nil)` when the
`Authenticator` held no `totp.Manager`, and `Authenticate`'s MFA gate read that
as "this user has no second factor". `RequireMFAWhenEnrolled` is
`MFAEnforcement(0)` — `EnforceMFA` — so a deployment that never touched the
field believed MFA was on.

The exploit needs no attacker sophistication, only an ordinary wiring mistake.
An application builds one `totp.Manager` for its enrolment endpoints, builds
`basic.Authenticator` for sign-in, and does not pass `Config.TOTPManager`. Both
share a credential store, so the enrolment is real and confirmed. Reproduced
against v1.1.2 through the exported API only:

```
constructor accepted EnforceMFA with no TOTPManager: true
factor is genuinely enrolled+confirmed: enabled=true err=<nil>
RESULT: *** MFA BYPASSED *** password alone returned user TknSna_W_brKOUmL41J3vg
auth.IsTOTPEnabled reports: false (the store says true)
```

The store said the factor was confirmed the whole time. The authenticator said
no, because of how the caller had wired its objects.

This is not reachable through the primitives — `totp.Manager` on its own is
correct, and a scan of every `== nil` dependency guard in the library found
exactly two that answer with a benign value instead of an error, both of them
these. Every other nil dependency fails closed with a named error. The defect
exists only because one component orchestrates two others and degrades, rather
than refusing, when half-wired.

**Status: fixed.** Both methods now answer from the credential store via
`totp.LookupEnrollment`, which needs no `Manager`, no issuer and no `Cipher`.
The store is the authority on whether a factor exists; how the caller wired its
objects is not.

Two alternatives were rejected. Rejecting `EnforceMFA`-with-nil-manager at
construction would break every deployment that legitimately has no second factor
at all, which is not acceptable in a patch release. Returning an error from the
gate when it cannot determine enrolment would do the same at sign-in. Consulting
the store is correct in all three wirings and breaks none of them.

`LookupEnrollment` deliberately does not apply the stored-encoding policy that
`Manager` enforces (F-33): it classifies state only, so a downgraded row reports
as confirmed rather than being rejected. That direction is the safe one for a
gate — it demands the second factor — but it is why the function is an enrolment
check and never an authentication decision. Validating a code stays on `Manager`,
which does apply the policy.

The general rule this finding establishes, and the one v2 is designed around: a
security question whose wrong answer is a bypass must not be answered from
optional wiring.

---

## 4. Release strategy

Go's module rules put any major version at or above 2 on a `/v2` import path, so
"a breaking change" and "a module path change" are the same event. The work is
therefore split by whether a fix can keep downstream code compiling.

**v1.x — every fix that preserves compilation.** Behaviour changes that close a
vulnerability ship here as `fix:`, because a change that removes an
exploitable behaviour is a bug fix, not a breaking change. Anything destined for
removal is _meant_ to get a `// Deprecated:` marker in the same release, so
`staticcheck` warns downstream immediately. That is the intent; §4.2 records
where the tree does not meet it yet.

"Preserves compilation" is not the same as "preserves behaviour", and this
branch spends the difference deliberately: a control that is off by default
protects nobody, so several fixes change what an unchanged caller observes at
run time. Every one of them is enumerated in §7, which is the section a consumer
upgrading within v1.x has to read.

**v2 — the re-architecture.** Removals, interface reshaping, and the controls
whose correct form only exists after the removals.

| Item                                                      | Lands | Why                                                                                                                  |
| --------------------------------------------------------- | ----- | -------------------------------------------------------------------------------------------------------------------- |
| F-01 … F-21 fixes                                         | v1.x  | signature-preserving                                                                                                 |
| F-24 … F-28 (WebAuthn) and F-31 … F-34 (fix-work defects) | v1.x  | signature-preserving                                                                                                 |
| F-29 (WebAuthn enumeration oracle)                        | v2    | collapsing two exported sentinels changes behaviour invisibly; the real fix needs an RP secret and the API to set it |
| Deprecation markers                                       | v1.x  | gives downstream a full release of warning                                                                           |
| `session.Manager.Rotate`                                  | v1.x  | new method, additive                                                                                                 |
| Secure-by-default constructor validation                  | v1.x  | behaviour only                                                                                                       |
| Remove `provider/*` vendor files                          | v2    | deletion                                                                                                             |
| Remove `audit/wrapper.go`                                 | v2    | deletion                                                                                                             |
| `storage/memory.go` → `storagetest`                       | v2    | moves out of the public surface                                                                                      |
| Remove `middleware/basic.go`                              | v2    | deletion                                                                                                             |
| Drop `UserStore` from library dependencies                | v2    | changes four constructors                                                                                            |
| `SessionStore.DeleteAllForUser`                           | v2    | adding to a published interface breaks implementors                                                                  |
| `attempt` limiter package                                 | v2    | designed once, against the v2 shape                                                                                  |
| Per-tenant `ProviderResolver`, `JITPolicy`                | v2    | not features — the residue of removing find-or-create                                                                |

Rate limiting and JIT gating are deliberately _not_ in v1. Adding a `JITPolicy`
hook to a code path that v2 deletes outright is designing the same thing twice.

### 4.1 What v2 removes

The library is 5,749 lines excluding tests and examples.

| Removal                                 | ~lines | Reason it is not a primitive                                                                                                       |
| --------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| `provider/*` vendor files               | 900    | configuration, not logic; OIDC discovery already covers every OIDC-capable provider from an issuer URL alone. Zero coverage today. |
| `audit/wrapper.go`                      | 652    | see F-22                                                                                                                           |
| `storage/memory.go` from the public API | 666    | ships an in-memory identity store as public API; becomes a conformance harness downstream implementors run against their own store |
| `middleware/basic.go`                   | 77     | see F-15                                                                                                                           |
| OIDC user create/lookup                 | 60     | see F-01                                                                                                                           |
| `basic` user CRUD                       | 80     | the library hashes and verifies; it does not own the row                                                                           |

Roughly 2,400 lines — 42 % of the library, and the bulk of what is currently
untested.

### 4.2 Known gaps in the deprecation programme

The `// Deprecated:` markers actually present in the tree, checked against the
removal list above:

| v2 removal                                                                                 | Marker present? | Where                                                                      |
| ------------------------------------------------------------------------------------------ | --------------- | -------------------------------------------------------------------------- |
| `provider/*` vendor constructors                                                           | yes             | all ten vendor files                                                       |
| `audit/wrapper.go`                                                                         | yes             | the wrapper types and constructors                                         |
| `middleware/basic.go`                                                                      | yes             | the middleware, both constructors and `Middleware`                         |
| OIDC user create/lookup                                                                    | yes             | `Config.UserStore`, `findOrCreateUser`, `CallbackResult.User`/`.IsNewUser` |
| `basic` user CRUD                                                                          | yes             | `Register`                                                                 |
| `jwt.Config.UserStore`                                                                     | yes             |                                                                            |
| Migration shims (`ActivateOnGenerate`, `AllowLegacyPlaintextSecrets`, `AllowPasswordOnly`) | yes             |                                                                            |
| **`storage/memory.go` → `storagetest`**                                                    | **no**          | **nothing in the file carries a marker**                                   |

`storage/memory.go` is the gap. §4.1 lists it as leaving the public API in v2,
and none of the five exported types (`InMemoryUserStore`,
`InMemoryCredentialStore`, `InMemorySessionStore`, `InMemoryTokenStore`,
`InMemoryOIDCStateStore`) or their five constructors carries a
`// Deprecated:` marker — `grep -c 'Deprecated:' storage/memory.go` returns 0.
Downstream gets no `staticcheck` warning, so the release of notice the strategy
above promises is not being served for the one removal a demo or test suite is
most likely to depend on. The package doc comment in `storage/storage.go` states
the move in prose, which is documentation, not a machine-checkable warning.

It is recorded here rather than fixed because `storage/memory.go` is owned by
another agent in this wave. The remedy is one marker per exported type and
constructor, worded to name the replacement rather than to imply the type is
unsafe — these stores are correct, they are simply not public API in v2:

```go
// Deprecated: the in-memory stores move to a conformance-harness package in v2
// and leave the public API. Use them for development, examples and tests only;
// implement storage.UserStore against your own database for anything else.
```

There is a second, milder shortfall: a v2 removal that is _behaviour_ rather
than a symbol cannot carry a marker at all. `HandleCallback` and
`GetAuthorizationURL` are marked, but "provisioning without a `CreatePolicy`"
and "a TOTP factor armed without `Confirm`" are behaviours that simply stopped
happening, and no compiler or linter can warn about those. §7 is the only
warning a consumer gets, which is why it is written as a checklist rather than
as prose.

---

## 5. Tooling

Before this branch there was no `.golangci.yml`, so the linter ran on defaults.
The table below is what `.golangci.yml` enables **today**, checked line by line
against the file rather than against the plan that was written before the
configuration existed.

| Named in the original plan                               | State in `.golangci.yml`                                                                                                                                                                                                                                                                                                                                                        |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `gosec`                                                  | enabled, `severity: low`, `confidence: low`, only `G115` excluded (it duplicates `govet`'s conversion checks)                                                                                                                                                                                                                                                                   |
| `errcheck` strict, blank assignment disallowed           | enabled through `default: standard`, with `check-blank: true` and `check-type-assertions: true`                                                                                                                                                                                                                                                                                 |
| `bodyclose`, `noctx`, `contextcheck`                     | all three enabled; `noctx` is exempted only for `httptest.NewRequest`, which cannot carry a context                                                                                                                                                                                                                                                                             |
| `errorlint`, `nilnil`, `exhaustive`, `copyloopvar`       | all four enabled (`errorlint` with `errorf`/`asserts`/`comparison`, `exhaustive` with `default-signifies-exhaustive`, `nilnil` with `detect-opposite`)                                                                                                                                                                                                                          |
| `forbidigo` banning `math/rand`                          | enabled for both `math/rand` and `math/rand/v2`, with `analyze-types: true` so an import alias cannot dodge it                                                                                                                                                                                                                                                                  |
| `forbidigo` banning `time.Now` "inside comparison paths" | **not implemented.** No such rule exists, and `forbidigo` cannot express "inside a comparison path" — it matches a pattern against a package, not against a data flow. The claim was aspirational; the protection it described is delivered by the tests instead (`TestSession_ExpiryBoundary`, `TestJWT_ExpiryNotBeforeAndClockSkewBoundaries`, `TestTOTP_SkewWindowBoundary`) |
| `depguard`                                               | enabled, `list-mode: strict`, allow-list of `$gostd` plus the six direct dependencies                                                                                                                                                                                                                                                                                           |
| `revive` against the Google Go style guide               | enabled at `severity: error` with 24 named rules, including `exported` and `package-comments`                                                                                                                                                                                                                                                                                   |
| `paralleltest`                                           | enabled, with a documented shrinking ledger of files that have not adopted `t.Parallel` and three named tests that must stay sequential                                                                                                                                                                                                                                         |
| `testifylint`                                            | **deliberately absent.** Nothing in this module imports `stretchr/testify` — the `go.sum` entry is another module's transitive test dependency — so the linter would have nothing to inspect. The config says so at the point of absence                                                                                                                                        |

Enabled beyond the plan: `gocritic` (diagnostic, performance and style tags),
`misspell`, `prealloc`, `unconvert`, `wastedassign`, `staticcheck` with `all`
checks, `govet` with `enable-all` minus `fieldalignment`, and the `gofmt` /
`goimports` formatters. `issues.uniq-by-line: false` is set on purpose: with the
default, `gosec`'s `G404` and `forbidigo`'s `math/rand` ban landing on the same
call would silently drop one of the two, and which one survived would be an
ordering accident.

CI (`.github/workflows/ci.yml`) runs, as separate jobs: `go test -race
-covermode=atomic ./...` followed by the per-package coverage-floor gate;
`go vet`, `gofmt` and `golangci-lint`; a library build; `govulncheck ./...`;
every `Fuzz*` target discovered by `go test -list` at a 30-second budget each,
failing the job if it discovers none; and a build-and-vet of
`examples/complete`, which has its own `go.mod` and would otherwise rot silently
when the API changes.

The coverage gate reads `.coverage-floor`, which records a measured floor per
package and **fails on a package it has no floor for** — an ungated package is
indistinguishable from a package at 0 %, which is the hole F-23 was.

---

## 6. Test programme

The goal is not coverage percentage. It is that **each fix ships with a test
that fails when the fix is reverted**, and that each test names the attack it
defends against. A test that still passes with its fix removed is not evidence.

Adversarial suites, organised by the real defect classes they mirror:

**JWT** (`auth/jwt/adversarial_test.go`) — `alg: none`; algorithm confusion (an
HS256 token signed with the RS256 public key); signing-method substitution on
the revoke path; oversized/deeply-padded token denial of service (the
CVE-2025-30204 class, asserted against a `TotalAlloc` delta); `aud` confusion
and cross-audience replay (the GHSA-mh63-6h87-95cp class); `exp`/`nbf` and
clock-skew boundaries; token-type claim confusion; refresh token presented as
bearer (F-02); cross-issuer replay (F-03); truncated or extended signing keys;
a refresh token minted without a `jti`.

_Not written:_ `kid` injection via path traversal. This package resolves no key
by `kid` — there is one configured key or key pair and `keyFunc` never consults
the header — so the attack has no surface here. It is listed as not applicable
rather than quietly dropped.

**OIDC** (`auth/oidc/adversarial_test.go`, `oidc_hardening_test.go`) —
unverified-email takeover (F-01, the CVE-2023-28131 class); cross-provider and
foreign-subject adoption; the subject backfill and its refusal of a different
subject afterwards; identity-provider mix-up between two registered connections;
PKCE challenge, verifier possession, and omission; nonce omission and replay;
login CSRF with and without the browser binding (F-16); state replay, expiry and
concurrent single-use; a store that drops a control failing closed (F-32);
claim-allow-list containment (F-21).

_Not written:_ `redirect_uri` exact-match enforcement — the redirect URI is
matched by the authorization server, and this client only chooses which of its
own configured URLs to send; and **JWKS fetch against an internal address or a
rebinding DNS answer (F-20)**, which does not exist in any form. What exists is
`TestDefaultHTTPClientIsBounded`, `…RefusesAnOversizedBody` and
`…AllowsABodyAtTheLimit`: they prove the timeout and the response-size cap, and
prove nothing at all about which addresses a request may reach. That is
consistent with the F-20 fix, which deliberately ships no dialer policy — but
the claim that the suite tests an internal-address fetch was false and is
withdrawn. A deployment's egress policy remains untested by this repository.

**WebAuthn** (`auth/webauthn/adversarial_test.go`) — foreign origin on both
ceremonies; RP ID hash confusion; ceremony-type substitution; challenge
substitution, replay, single use and burn-on-failure; forged, tampered and
malleable signatures; user-presence flag; user-handle mismatch; credential-ID
collision across two users; unregistered and deleted credentials; sign-counter
rollback and the counterless-authenticator exemption (F-25); counter-persistence
failure (F-26); the OIDC namespace split (F-27); backup-flag round trip (F-28);
oversized credential IDs; nil and malformed ceremony payloads.

_Not written:_ attestation-type downgrade. The package requests no attestation
and stores `AttestationType` without acting on it, so there is no policy to
downgrade; a v2 that adds attestation policy needs this test with it.

**TOTP** (`auth/totp/adversarial_test.go`) — code replay inside the window
(F-08) including the whitespace bypass (F-31) and its confirmation-path twin;
concurrent replay admitting exactly one; skew boundary and guard retention
across the whole window; guard failing closed and resisting flooding by one
account; enrol-without-confirm (F-07); secret and backup-code confidentiality at
rest, single use, cross-user isolation and regeneration (F-06); payload-tag
downgrade (F-33); secret entropy.

**Password** (`auth/basic/adversarial_test.go`) — 72-byte prefix siblings
(F-10); the ceiling measured in bytes rather than runes; embedded NUL;
account-existence timing on both sign-in and reset-token generation (F-09),
measured statistically with a tolerance wide enough not to flake in CI but tight
enough to catch the removal of the dummy comparison; reset and verification
tokens unusable from the store (F-05); rollback failure surfaced (F-11);
delete-failure not reported as success (F-12); MFA enforcement (the MFA-bypass
fix).

**Session** (`session/adversarial_test.go`) — fixation across authentication and
the dead pre-rotation identifier (F-14); rotation not extending lifetime,
leaving two live sessions, or aliasing the old session's data; expiry boundary
and an expired entry a hostile store still serves; identifier entropy;
concurrency under `-race`.

**Middleware** (`middleware/adversarial_test.go`) — refresh token as a bearer
credential (F-02); hostile claim shapes; header and cookie extractor attacks;
response-header injection through a cookie value; context-key collision and type
confusion; the zero-value `CookieWriter` proven insecure exactly as documented.

**Fuzzing.** The claim that fuzz targets "cover every parser and decoder that
touches untrusted input" was not true and is not true now. There are **seven
`Fuzz` functions in the module, all in `auth/webauthn/adversarial_test.go`**:
`FuzzRegistrationCeremony`, `FuzzAssertionCeremony`, `FuzzDecodeSessionData`,
`FuzzCredentialTransportRoundTrip`, `FuzzCanonicalSignatureEncoding`,
`FuzzCredentialFlagMetadata` and `FuzzCeremonyTimeout`. They cover the two
ceremony entry points a browser posts to, the persisted session blob, the
transport and flag metadata round trips, and the ECDSA signature-encoding check.

Decoders with **no** fuzz target today: the JWT parse path in `auth/jwt`, the
state-record and metadata decode in `auth/oidc`, the stored TOTP payload and
backup-code decode in `auth/totp`, and the provider user-info JSON in
`provider`. Each is covered by hand-written hostile-input tests
(`TestJWT_MalformedTokenShapesRejectedWithoutPanic`,
`TestOIDC_CorruptStateMetadataIsNeverReadAsAnAbsentControl`,
`TestTOTP_MalformedCodesRejectedWithoutPanic`,
`TestVendorExtractors_TypeConfusedPayloadsDoNotPanic`), which is a weaker
guarantee than fuzzing and is stated as such. The CI fuzz job runs whatever
targets exist and fails when it finds none, so the number can only be raised
deliberately.

**Store conformance.** `RunConformance` exists and is hostile in the right way —
it asserts what an implementation must refuse — but it lives in
`storage/conformance_test.go` in package `storage_test`. **A `_test.go` file is
not importable, so no downstream store can run it today.** The file's own header
says as much: in v2, when `storage/memory.go` leaves the public API, it becomes
the `storagetest` package this section calls for and moves verbatim, since
nothing in it reaches into package internals. Until then it proves the in-memory
stores conform and serves downstream only as a specification to read. The
present tense in the earlier wording described v2, not the tree.

---

## 7. Migration notes for consumers

**A v1.1.1 consumer still compiles against this branch. It does not still
work.** No exported signature changed, no exported symbol was removed and no
field changed type — that property was verified mechanically and holds — but a
control that is off by default protects nobody, so a dozen fixes change what an
unchanged caller observes at run time. An earlier draft of this section claimed
"upgrading within v1.x requires no code changes" and listed three observable
differences. That was written before the fixes landed and was wrong on both
counts.

Read the whole list before upgrading. It is ordered by how likely each item is
to take a working deployment down, most severe first, and every item names its
remediation.

### The short version

| #   | What breaks                                                           | Remediation                                                  |
| --- | --------------------------------------------------------------------- | ------------------------------------------------------------ |
| 1   | Every first-time OIDC sign-in is refused                              | set `Config.CreatePolicy`                                    |
| 2   | Every OIDC callback fails on a store that drops unknown fields        | persist `OIDCState.Metadata` verbatim                        |
| 3   | Sign-in returns `ErrMFARequired` for any user with a confirmed factor | handle it, or `AuthenticateWithTOTP`, or `AllowPasswordOnly` |
| 4   | `NewTokenManager` refuses a short HMAC secret at startup              | use ≥ 32/48/64 bytes for HS256/384/512                       |
| 5   | TOTP enrolment no longer arms itself                                  | add a `Confirm` step, or `ActivateOnGenerate`                |
| 6   | `GetTOTPSecret` returns digests, not codes                            | show `Secret.BackupCodes` once at enrolment                  |
| 7   | OIDC refuses an unverified or absent email                            | provider-dependent; see below                                |
| 8   | Some pre-existing OIDC accounts need `LinkPolicy`                     | set `Config.LinkPolicy`                                      |
| 9   | Passwords over 72 bytes are refused                                   | surface `ErrPasswordTooLong` in the UI                       |
| 10  | `ValidateToken` rejects refresh tokens                                | use `RefreshAccessToken`                                     |
| 11  | Token metadata is dropped                                             | `Config.MetadataAllowlist`                                   |
| 12  | Pre-upgrade reset/verification links stop working                     | wait out the TTL                                             |
| 13  | Mutating a `*User` from an in-memory store no longer persists         | call `UpdateUser`                                            |
| 14  | `CreateSession` on a live ID returns `ErrAlreadyExists`               | stop reusing IDs                                             |
| 15  | Middleware constructors panic on a nil dependency                     | use the `…WithError` forms                                   |
| 16  | WebAuthn ceremonies in flight across the deploy fail                  | expected; one ceremony                                       |
| 17  | GitHub sign-in for an account with no public email                    | request `user:email` and check `/user/emails`                |
| 18  | The unbound OIDC entry points still carry F-16                        | move to the `…WithBinding` pair                              |

### 1. Every first-time OIDC sign-in is refused (F-01)

`HandleCallback` no longer provisions an account for an assertion that matches
none. With `Config.CreatePolicy` nil — which is every v1.1.1 configuration,
since the field did not exist — it returns `ErrAccountCreationRefused`. Existing
users keep signing in; every new one is turned away.

This is the single most consumer-breaking change on the branch, and it is
deliberate: the library cannot answer the question provisioning asks. An
assertion carries an email address and a flag saying the provider verified it;
neither tells the library whether the connection that sent them is entitled to
that address, and in a bring-your-own-connection deployment the tenant
administrator sets that flag.

```go
// Restore the previous behaviour verbatim:
CreatePolicy: authoidc.AllowAccountCreation,

// Or decide properly — this is the shape the fix is asking for:
CreatePolicy: func(ctx context.Context, info *authoidc.UserInfo) (bool, error) {
    return connectionOwnsDomain(info.Provider, info.Email), nil
},
```

### 2. Every OIDC callback fails on a store that drops unknown fields (F-32)

PKCE, the browser binding and the nonce are carried in new `storage.OIDCState`
fields **and** in mirrored reserved keys inside `Metadata`. A store that
reconstructs the struct from the columns it knows about returns a record with
neither copy, and the callback fails closed with `ErrStateControlMissing` rather
than proceeding without the control.

Remediation: persist `Metadata` verbatim — including keys the store does not
recognise — or add columns for `CodeVerifier`, `BindingHash` and `Nonce`. Either
one suffices; the library only needs one of the two copies. Symptom to watch
for: every sign-in failing immediately after deploy, with no traffic reaching
the provider.

### 3. `Authenticate` returns `ErrMFARequired` (the MFA-bypass fix)

`basic.Authenticator.Authenticate` used to return the user on a correct password
even when that user held a confirmed second factor, which made every route
reachable with one factor. It now returns `ErrMFARequired`, and the zero value
of the new `Config.RequireMFAWhenEnrolled` is the enforcing one.

**`ErrMFARequired` is not a failed sign-in.** A handler that treats any non-nil
error as "invalid credentials" locks out every enrolled user. Either collect a
code and call `AuthenticateWithTOTP` (both factors, one call), or set
`RequireMFAWhenEnrolled: basic.AllowPasswordOnly` if the application runs its
own second-factor step after `Authenticate`.

Two things narrow the blast radius, and both are deliberate. A deployment that
never set `Config.TOTPManager` sees no change at all — `IsTOTPEnabled` reports
false with no manager configured, so the gate cannot fire. And a TOTP enrolment
still awaiting `Confirm` does not trigger it either: that factor has never
validated a code, so gating on it would lock the user out of their own
half-finished enrolment (F-07).

### 4. `NewTokenManager` refuses a short HMAC signing key (F-04)

RFC 7518 §3.2 requires an HMAC secret at least as long as the hash output, and
the constructor now enforces it: **32 bytes for HS256, 48 for HS384, 64 for
HS512**. A passphrase-length secret that v1.1.1 accepted now fails at startup
with `ErrInvalidKeyConfig`.

This is a startup failure, not a runtime one, which is the intended trade: the
alternative is a library documenting a floor it does not apply. Generate 32
bytes from `crypto/rand` and carry them hex- or base64-encoded in the
environment. The same constructor now also rejects an asymmetric
`SigningMethod` paired with a `[]byte` `SigningKey`, which used to fail on the
first token minted instead.

### 5. TOTP enrolment no longer arms itself (F-07)

`GenerateSecret` stores the factor **pending**. Until `Confirm(ctx, userID,
code)` succeeds: `IsEnabled` reports `false`, `Validate` and `ValidateBackupCode`
return `ErrPendingConfirmation`, and `RegenerateBackupCodes` refuses.

Add the confirmation step every mainstream implementation has — render the QR
code, ask for one code, call `Confirm` — or set
`Config.ActivateOnGenerate: true` to keep the old behaviour and its lockout
risk. The flag is deprecated on arrival. `IsPending` distinguishes "never
enrolled" from "enrolled, not confirmed", and `Disable` cancels a pending
enrolment so the user can restart without an administrator.

### 6. `GetTOTPSecret` returns digests, not printable backup codes (F-06)

Backup codes are hashed unconditionally, cipher or no cipher. The `[]string`
that `CredentialStore.GetTOTPSecret` returns therefore holds keyed digests, and
the plaintext exists exactly once — in `Secret.BackupCodes` from
`GenerateSecret`, and in the slice `RegenerateBackupCodes` returns.

An application that re-displayed a user's backup codes by reading them back out
of the store will now print digests. Show them once at enrolment and offer
regeneration afterwards; there is no way back to plaintext and none is planned.
The stored secret itself also changes shape unless no `Cipher` is configured
_and_ `ActivateOnGenerate` is set — see F-06 for the exact encoding, which a
store must round-trip byte for byte.

### 7. OIDC refuses an unverified or absent email address (F-01)

`findOrCreateUser` returns `ErrEmailNotVerified` when the provider asserts
`email_verified: false`, and `ErrMissingEmail` when it asserts none. Two
populations are affected: providers that do not emit `email_verified` at all,
and users whose account genuinely carries no verified address.

This one has no compatibility flag, because "believe an unverified email claim"
is the CVE-2023-28131 defect itself. Either configure the connection to release
a verified address, or stop using the user-store path — leave `Config.UserStore`
nil, take `CallbackResult.UserInfo`, and apply the application's own rule. That
is also the v2 shape.

### 8. Some pre-existing OIDC accounts need a `LinkPolicy` (F-01)

The auditor's draft of this section claimed every pre-existing federated account
hits `ErrAccountLinkRequired` because v1.1.1 never recorded a subject. **That is
not what the source says.** v1.1.1's `findOrCreateUser` wrote
`Metadata["provider_sub"] = userInfo.Subject` on every account it created, and
`recordedProviderSubject` reads that key as one of the two locations it accepts.
An account created by v1.1.1's own OIDC path, in a store that round-trips
`Metadata`, matches on the first sign-in after the upgrade and nothing happens.

The remediation landed too: `adoptUnrecorded` backfills an account that carries
_no_ recorded subject but was created by the same provider, pinning it on the
way through. It is trust on first use and it lasts exactly one sign-in — from
the backfill onwards a different subject is refused — and a failed write fails
the callback rather than leaving the account unpinned.

What genuinely remains, and needs `Config.LinkPolicy` to clear:

- **An account whose `Provider` differs from the asserting connection.** The
  commonest case is an account created by `basic.Register` (`Provider: "basic"`)
  whose owner now signs in with Google. v1.1.1 adopted it on the email address
  alone; that is the nOAuth defect, so it is refused.
- **An account with an empty `Provider`** — anything the application created
  itself — for the same reason.
- **A recorded subject that is present but unusable**: the wrong type after a
  JSON round trip, or an empty string. That is a damaged record, not an absent
  one, and it fails closed rather than being backfilled.
- **A store that persists neither `ProviderSubject` nor `Metadata`** never
  records the backfill, so the account is re-pinned on every sign-in and stays
  one provider-name check away from adoption. Fix the store.

`LinkPolicy` is consulted for all of these, and also for the backfill itself
when one is configured, so an application can police even trust-on-first-use.

### 9. Passwords longer than 72 bytes are refused (F-10)

`Register`, `ChangePassword`, `ResetPassword` and `CompletePasswordReset` return
`ErrPasswordTooLong` above `MaxPasswordLength`. bcrypt ignored everything past
72 bytes, so the alternative is authenticating a 100-character passphrase by its
first 72 — and colliding two different passwords that share a prefix. The bound
counts **bytes**, so a multi-byte passphrase reaches it before its character
count suggests.

`Authenticate` deliberately does _not_ apply the ceiling: a credential
registered before the fix must keep verifying. Surface the sentinel in the UI;
a generic "invalid password" on a password the user just typed twice is how this
becomes a support ticket.

### 10. `ValidateToken` rejects refresh tokens (F-02)

`ValidateToken` now means `ValidateAccessToken`. `JWTMiddleware` rejects a
refresh token presented as a bearer credential, without saying why in the
response body. Code that deliberately presented one was exploiting the defect
and must use `RefreshAccessToken`. `ValidateRefreshToken` exists for a caller
that needs to inspect one.

### 11. Tokens no longer carry `user.Metadata` (F-21)

Nothing is copied into the `metadata` claim unless the key is named in
`jwt.Config.MetadataAllowlist`; likewise `oidc.Config.ClaimAllowlist` governs
what reaches a created user's metadata. A consumer reading claims out of the
metadata map must opt in, key by key. A JWT is base64, not encrypted.

### 12. Pre-upgrade reset and verification links stop working (F-05)

Tokens issued before the upgrade do not validate, because the library now hashes
before storing and before lookup. The reset TTL is one hour and the verification
TTL is 24 hours, so the window closes on its own; users re-request. A store
holding legacy plaintext rows is not migrated and is not readable — the values
are one-way from here.

### 13. The in-memory stores clone on read

`GetUserByID`, `GetSession`, `GetState` and the credential getters return
copies. Mutating a returned `*User` and expecting the store to have changed —
which worked by accident, because the pointer was the stored object — now
changes nothing. Call `UpdateUser`. This only affects the `storage.InMemory*`
types (development, examples and tests); a real database store never had the
aliasing behaviour to begin with.

### 14. `CreateSession` on a live ID returns `ErrAlreadyExists`

The interface now documents it and the in-memory store enforces it: creating a
session over an ID that is still live is refused rather than silently replacing
it. Two 256-bit random IDs do not collide, so a collision is a defect or an ID
that did not come from `session.Manager` — the shape of a fixation attempt. An
_expired_ entry is still replaced, so this does not interfere with reuse after
expiry, and it is what makes `session.Manager.Rotate` safe.

### 15. Middleware constructors panic on a nil dependency

`NewJWTMiddleware` and `NewBasicAuthMiddleware` panic when their dependency is
nil, at construction. Their v1 signatures return no error, and the alternative
is a nil dereference inside the handler on the first _unauthenticated_ request —
which lets an anonymous caller choose when the server crashes. Use
`NewJWTMiddlewareWithError` or `NewBasicAuthMiddlewareWithError` to handle it as
a value. Both `basic` middleware constructors are deprecated (F-15).

### 16. WebAuthn: ceremonies, timeouts and the counter (F-24 … F-28)

- `Config.Timeout` is milliseconds, defaults to five minutes, and is refused at
  construction if negative or above fifteen minutes.
- Ceremony records are now checked for the `webauthn` provider tag and for the
  fields this package wrote, and every failure collapses into one sentinel. The
  old build wrote the same tag, so a ceremony spanning the deploy is not broken
  by the check — it was already broken by F-24, whose 300 ns TTL had expired it
  long before the browser answered.
- An assertion whose signature counter does not advance is refused with
  `ErrCredentialCloned`. An authenticator reporting 0 on both sides is exempt.
- A failed counter write now fails the ceremony with `ErrSignCountNotPersisted`
  instead of printing to stdout. A `CredentialStore` that quietly ignores
  counter updates will start returning this; that is the control working.

### 17. GitHub sign-in for an account with no public email

`NewGitHubProvider`'s extractor used to set `EmailVerified: true`
unconditionally, which asserted that an empty string was a verified address. It
now tracks the address: `userInfo.EmailVerified = userInfo.Email != ""`. GitHub
only lets a verified address be selected as the public profile email, so this is
as strong an inference as `GET /user` supports — but a user who publishes none
now arrives with no email, which item 7 refuses.

For a hard guarantee, request the `user:email` scope the constructor already
asks for, call `GET /user/emails`, and take the entry whose `primary` and
`verified` are both true. That means supplying an extract function of your own
through `NewOAuth2Provider`, which is where every vendor constructor is headed
in v2 anyway.

### 18. The unbound OIDC entry points are unchanged, and still exposed (F-16)

`GetAuthorizationURL` and `HandleCallback` keep working exactly as they did.
That is the problem: a flow started there records `StateBindingUnbound` and has
no login-CSRF protection. The deprecation notice is the only signal an unchanged
caller gets. Move to `GetAuthorizationURLWithBinding` /
`HandleCallbackWithBinding`, store `AuthorizationRequest.Binding` in a cookie
(see `BindingCookieName`), and present it at the callback.

### What did not change

Every exported signature, every exported symbol, every exported field type and
every package path. Deprecation warnings appear for the symbols v2 removes, with
the exception recorded in §4.2. Nothing is deleted in v1.

---

## 8. Audit outcome

The fixes for F-01 … F-23 were then put in front of **two independent
adversarial reviews**, neither primed with the reasoning above, whose brief was
to attack the remediation rather than the original library. They found real
defects in the fix work. That is the finding worth recording: a fix written
against a threat model is not the same thing as a fix that survives someone
attacking it.

### What the reviews found, after the fixes

| Defect                                   | Where the fix went wrong                                                                                                                                                                     | Register |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| TOTP replay bypass by whitespace         | the replay guard keyed on the raw submission while the validator compared a `TrimSpace`d one, so one accepted code had unboundedly many guard keys                                           | F-31     |
| A dead field read as an absent control   | PKCE, the binding and the nonce were new `OIDCState` fields; a store that dropped them returned "no such control" and the flow proceeded without it — fail-open                              | F-32     |
| The TOTP payload tag was unauthenticated | the pending marker and cipher discriminator sat outside the ciphertext, so a store writer could downgrade a sealed secret to a plaintext one of their choosing, or arm an unconfirmed factor | F-33     |
| A 300-nanosecond challenge TTL           | `StoreState(..., 300)` under a `// 5 min timeout` comment: the constant is a `time.Duration`. No WebAuthn ceremony could complete against a store that honours TTLs                          | F-24     |
| A blinded audit actor                    | the F-02 token-type pin made the audit wrapper's actor lookup impossible, so every successful `token.refresh` and `token.revoke` was recorded anonymously                                    | F-34     |

All five are remediated in the tree, each with a test that fails when the fix is
reverted. The same wave also closed the WebAuthn sign-counter rollback (F-25),
the stdout write (F-26), the shared state namespace (F-27) and the missing
backup flags (F-28).

Three of the five share one shape, and it is worth naming: **a control whose
input can go missing must refuse, not proceed.** The whitespace bypass, the
dropped state field and the rewritable payload tag are all cases where something
the fix depended on was absent or attacker-chosen, and the code read absence as
consent. §2's threat model says fail closed; the first round of fixes said it
and did not always do it.

### Measured coverage

Recorded in `.coverage-floor` from `go test -race -covermode=atomic ./...` on
this branch, against the F-23 baseline:

| package         | before | after  |
| --------------- | ------ | ------ |
| `auth/oidc`     | 0.0 %  | 94.1 % |
| `provider`      | 0.0 %  | 92.9 % |
| `auth/webauthn` | 0.0 %  | 85.9 % |
| `middleware`    | 31.2 % | 69.3 % |
| `audit`         | 56.3 % | 62.9 % |
| `storage`       | 76.1 % | 97.9 % |
| `auth/totp`     | 80.7 % | 86.2 % |
| `auth/basic`    | 82.6 % | 86.5 % |
| `session`       | 84.7 % | 88.2 % |
| `auth/jwt`      | 87.1 % | 90.3 % |

The floors committed to `.coverage-floor` sit two to three points below each
measurement, which absorbs timing-dependent drift under `-race` and nothing
else; a real regression is tens of points. CI fails on a package that has no
floor recorded at all.

Coverage is reported here because F-23 was a finding about it, not because it is
evidence of correctness. The evidence is that each fix has a test that fails
when the fix is reverted; `middleware` at 69 % is not a gap in the adversarial
suite, it is the amount of that package which is HTTP plumbing.

### What remains open

Stated plainly, because a hardening document that reads as reassurance is worse
than none:

- **F-29** — the WebAuthn `BeginLogin` account-existence oracle. Unfixable under
  the v1 signature freeze without silently changing what existing callers are
  told; deferred to v2 with a written plan and a test already shaped to become a
  regression guard. It is the only remaining `gap()` skip in the tree.
- **F-30** — `NewMicrosoftProvider` verifies no issuer. Accepted, documented at
  the constructor, and compensated only by a `tid` check the application must
  perform itself.
- **F-15, F-22, and the v2 column of §4** — the `basic` middleware, the audit
  wrapper and the `UserStore` coupling are deprecated, not gone. F-01's real fix
  is the v2 removal of find-or-create; what shipped in v1 is a set of refusals
  around a path that should not exist.
- **§4.2** — `storage/memory.go` carries no deprecation markers, so downstream
  gets no `staticcheck` warning for a v2 removal.
- **§6** — fuzzing covers `auth/webauthn` only; four other decoders of untrusted
  input have hand-written hostile-input tests instead. `RunConformance` is not
  importable by a downstream store until v2.
- **F-20** — the library ships no SSRF-safe dialer and no test that exercises
  one. Bounding the client is the library's job and is done; deciding which
  addresses it may reach is the deployment's, and remains untested here.

The line in §1 is the measure of whether this work succeeded, and by that
measure v1.x is a holding action: it makes the wrong side of the line refuse
loudly. v2 is where the wrong side stops existing.
