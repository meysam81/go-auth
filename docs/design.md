# go-auth design

v1 was an audit and a repair; v2 is the shape the repairs kept pointing at. This
is the canonical design: what exists and what is decided, each with its reason.
Each package's doc comment is its API contract; this document is why it has that
shape. Open questions are tracked outside this document.

Module `github.com/meysam81/go-auth/v2`, Go 1.26 or newer. G2 and G3 each get
a design pass, folded in here, before their code.

---

## 1. The line

> **The library verifies credentials and emits verified facts. It never creates,
> mutates, or owns identity.**

This is a testable structural property, and v1 produced the evidence for it. Of
the 35 findings of the v1 audit (§12), the primitives produced more in raw count
(21 against 12), but every one of them was fixable inside its own mechanism: add
PKCE, pin the token type, hash the token before it reaches the store. The
findings that could **not** be fixed inside v1 were all four of the ones where a
component owned an identity decision or wired two others together:

| Finding                              | Why it could not be fixed in v1                                                       |
| ------------------------------------ | ------------------------------------------------------------------------------------- |
| F-15 `BasicAuthMiddleware`           | bcrypt per request and no path to a second factor; only removal fixes it              |
| F-29 `BeginLogin` enumeration oracle | closing it changes what existing callers are told                                     |
| F-30 `NewMicrosoftProvider`          | a vendor convenience constructor that must disable issuer verification to work at all |
| F-35 half-wired MFA gate             | fixed only by removing the dependency on wiring, not by validating it                 |

F-35 shipped in a release and needed no attacker sophistication.
`IsTOTPEnabled` answered `(false, nil)` when the `Authenticator` held no
`totp.Manager`; the MFA gate read that as "no factor enrolled", and the password
alone returned the user while the store said the factor was armed. The rule it
establishes governs this whole design:

> **A security question whose wrong answer is a bypass must not be answered from
> optional wiring.**

### 1.1 What the library does

Verifies a password against a digest. Mints and verifies opaque tokens. Mints and
verifies JWTs. Runs the OIDC relying-party handshake and returns verified claims.
Runs WebAuthn ceremonies: registration, a second factor for a subject the caller
already authenticated, and discoverable passkey sign-in. Enrols and validates
TOTP. Classifies a set of authentication methods: multi-factor, phishing-
resistant, fresh. Counts failed attempts. Normalises identifiers. Emits audit
events.

### 1.2 What the application does

Owns the user record and its identifier. Decides whether an assertion refers to
an existing human. Decides tenancy. Decides whether to provision on first sight
and how accounts link. Decides which method sets may hold a session. Sends
email. Enforces RBAC. Persists everything, in its own schema, inside its own
transactions.

### 1.3 Threat model

Assumed adversaries, in the order they matter:

1. **An unauthenticated internet attacker** with the sign-in, registration,
   password-reset and OIDC callback endpoints, able to replay, truncate,
   reorder and forge anything not cryptographically bound.
2. **A malicious or compromised identity provider**, or a tenant administrator
   who legitimately controls their own IdP in a bring-your-own-connection
   deployment. This adversary can assert any claim set.
3. **An attacker with read access to the credential store**: a SQL injection
   elsewhere in the application, a leaked backup, a snapshot on shared storage.
   Anything persisted in a directly replayable form is a full compromise.
4. **An authenticated user escalating**: replaying their own tokens outside the
   intended window or scope, rolling back a counter, reusing a one-time code.

Out of scope: physical access to the running process, a compromised Go
toolchain, and side channels below a network-observable timing difference.

---

## 2. Packages

One module at the repository root. The phase is the delivery order.

| Package     | Owns                                                                                                                   | Phase |
| ----------- | ---------------------------------------------------------------------------------------------------------------------- | ----- |
| `amr`       | authentication methods (RFC 8176), factor classes, policy                                                              | G1    |
| `webauthn`  | registration, second-factor and passkey ceremonies                                                                     | G1    |
| `store`     | the single-use `FlowStore` and the shared error sentinels                                                              | G1    |
| `authtest`  | conformance suites, in-memory stores, a virtual authenticator                                                          | G1    |
| `challenge` | typed hand-off token, durable challenge state, step-up                                                                 | G2    |
| `attempt`   | failed-attempt budgets                                                                                                 | G2    |
| `totp`      | RFC 6238 enrolment and validation, durable replay guard                                                                | G2    |
| `recovery`  | recovery codes: generation, keyed digests with a key fingerprint, legacy verifiers                                     | G2    |
| `token`     | opaque secret mint, digest and verify (reset, verification, invitations)                                               | G3    |
| `session`   | session identifiers, rotation, revoke every session of a subject, refresh families with reuse detection, hashed tokens | G3    |
| `oidcrp`    | OIDC relying party: handshake in, verified claims out                                                                  | G3    |
| `httpx`     | outbound transport that refuses non-public addresses                                                                   | G3    |
| `jwtx`      | JWT mint and verify                                                                                                    | G3    |
| `hash`      | password hashing: pluggable, parameter-bounded; bcrypt first                                                           | G3    |
| `audit`     | event vocabulary, a `Logger` interface, a `log/slog` adapter                                                           | G3    |
| `httpmw`    | credential extraction middleware and the session cookie writer                                                         | G3    |
| `normalize` | PRECIS identifier normalisation                                                                                        | later |
| `batteries` | optional wired-up flows (§7)                                                                                           | later |
| `examples/` | runnable demonstrations and a reference SQLite store; not production code                                              | G1    |

| Phase | Ships as         | Exit                                                                                                                        |
| ----- | ---------------- | --------------------------------------------------------------------------------------------------------------------------- |
| G1    | `v2.0.0-alpha.N` | every §6.2 check has a virtual-authenticator test that fails when the check is removed; the suites pass against a SQL store |
| G2    | `v2.0.0-beta.N`  | its design pass, with the v1 parity table for its area (§9)                                                                 |
| G3    | `v2.0.0`         | its design pass; the parity tables cover every non-test file of v1                                                          |
| later | `v2.x`           | `hash` argon2id and other importers, `normalize`, an attestation policy, a reference SQL store as a package, `batteries`    |

The boundary is enforced by `.golangci.yml`, not by discipline. `depguard` runs
in strict mode with an allow-list of the standard library and the modules the
tree imports today (`go-webauthn/webauthn`); `amr` and `store` are standard
library only. A later phase adds `pquerna/otp`, `golang-jwt/jwt/v5`,
`coreos/go-oidc/v3`, `golang.org/x/crypto` or `golang.org/x/oauth2` in the change
that first imports it; any other module needs a decision here first. When
`batteries/` exists, a rule forbids every core package from importing it, and
lets `batteries/` import nothing the core does not already depend on.
`.dependency-footprint` lists what each package compiles in, so a dependency
upgrade that pulls in a new package shows up in review.

---

## 3. What v2 removes

| Removed                                 | Reason                                                                                                                                                                                                                                                                                                                            |
| --------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `provider/*` vendor constructors        | Configuration, not logic. OIDC discovery reaches every OIDC-capable provider from an issuer URL. They were untested in v1, and one (F-30) had to disable issuer verification to work. Replaced by `oidcrp` from an issuer URL plus documented recipes.                                                                            |
| `audit/wrapper.go`                      | 19 hand-mirrored decorators; F-22 and F-34 are the same defect twice. Replaced by events emitted from the primitives.                                                                                                                                                                                                             |
| `storage/memory.go` from the public API | Shipped an in-memory identity store as public API. Became `authtest`, a conformance harness.                                                                                                                                                                                                                                      |
| `middleware/basic.go`                   | F-15.                                                                                                                                                                                                                                                                                                                             |
| `storage.UserStore`                     | The coupling that made F-01 and F-35 expressible.                                                                                                                                                                                                                                                                                 |
| `basic.Authenticator`'s user CRUD       | The library hashes and verifies; it does not own the row.                                                                                                                                                                                                                                                                         |
| `oidc.findOrCreateUser`                 | F-01. Replaced by returning claims.                                                                                                                                                                                                                                                                                               |
| `auth/webauthn` as written              | The user handle was the application's user ID (the spec wants random bytes with no meaning); login was user-ID-first only, the F-29 oracle; no `excludeCredentials`; the counter was written blind, so concurrent assertions both passed the rollback check; backup flags lived in an untyped map. Replaced by `webauthn` (§6.2). |

The `Enrollment`/`LookupEnrollment` shape v1.1.3 added for F-35 survives as the
general pattern: enrolment state is read from the store, never inferred from
which objects the caller happened to construct.

---

## 4. The storage contract

The library keeps two kinds of state, under two contracts.

- **Durable credentials the application keeps and administers**: WebAuthn
  credentials and user handles in G1; TOTP secrets and recovery codes in G2.
  These are **typed**. Each package declares the narrow interface it calls; the
  application maps it onto its own tables and columns.
- **Short-lived ceremony state only the library reads**: the WebAuthn challenge
  and its session data, the OIDC handshake, a challenge in flight. This is
  **opaque**, held in one single-use `store.FlowStore`.

### 4.1 `FlowStore`

A `Flow` carries the ceremony kind that wrote it (the reader checks it), a
library-owned payload and an expiry. `Put` never overwrites a flow id. `Take`
fetches and consumes atomically and is never a get followed by a delete: on a
READ COMMITTED database two concurrent callers would both see the flow unused.
The SQL shape is
`UPDATE flows SET used_at = ? WHERE id = ? AND used_at IS NULL AND expires_at > ?`,
judged by the affected-row count. Missing, expired and consumed flows all return
`store.ErrNotFound`: the difference is an oracle.

Flow ids are 256-bit `crypto/rand` values. A flow is never extended or
rewritten: a ceremony that needs a second round mints a new flow.

The flow store must be as confidential and integrity-protected as the credential
store. A WebAuthn payload carries the challenge, the RP ID, the allowed
algorithms, the user-verification requirement and the conditional-create
exemption from user presence; whoever can rewrite it can relax them. The library
cross-checks what it can derive from its own configuration (the RP ID, the
algorithms, that no ceremony is bound to a single origin, that its two
user-verification records agree) and refuses a mismatch as a store fault; the
rest it must trust.

### 4.2 Rules for typed stores

1. **Stores are passed per call, never held.** Every function that touches state
   takes its store as an argument, so the application passes one bound to its own
   transaction: a new credential, the sessions it revokes, the audit row and the
   outbound notice commit together or not at all. The library never opens,
   commits or assumes a transaction. Two writes must persist even when a
   `Finish` fails, so neither may ride a transaction the application rolls back
   on failure: the flow `Take` (pass a `FlowStore` outside it, or a rolled-back
   failure leaves the flow reusable) and `MarkCloneSuspected` (commit it, or give
   it a store of its own, before rolling back, or the clone is forgotten).
2. **Every invariant that needs atomicity is one named store method, and the
   library calls it itself.** Its contract states the SQL shape and the
   concurrency guarantee, and an `authtest` suite races it. G1's:
   `FlowStore.Take`, `CredentialStore.Insert` (credential ID unique across every
   subject), `CredentialStore.RecordAssertion` (conditional on the stored
   counter), `HandleStore.Ensure` (create-if-absent).
3. **A field the library needs is never answered by its zero value.** A loaded
   credential with an empty ID, public key or RP ID, a zero `CreatedAt`, or a
   `Version` that is zero or above the current one is a store fault (fail
   closed). A `Begin` returns it as an infrastructure failure that matches no
   sentinel; a `Finish` refuses the ceremony with `ErrInvalidCredentials`.
   Booleans cannot be checked this way, which is what rule 4 is for.
4. **The conformance suite round-trips every exported field.** `authtest` fills
   each exported field of every stored struct with a distinct non-zero value by
   reflection and requires deep equality on the way back, so a field added in a
   later release fails the application's CI until its store persists it (F-32).
5. **A published interface never gains a method.** A new capability is a new
   interface, detected with a type assertion and documented as optional. A
   struct may gain fields; rule 4 catches stores that drop them.
6. **Not-found is a store concern.** Stores return `store.ErrNotFound` where a
   method's contract allows it; the authentication functions never surface it
   (§5).
7. **Times are instants kept to the microsecond**, the finest PostgreSQL and
   MySQL keep. A store may truncate or round below it and return any location;
   the suites write instants with a sub-microsecond remainder. A flow is usable
   until its `ExpiresAt`, not at it (`expires_at > now`); the suites cannot test
   that instant without a clock the `FlowStore` interface lacks, so the rule
   stands on the contract text.

---

## 5. Errors and enumeration

One sentinel, `ErrInvalidCredentials`, answers an unknown identifier, a subject
with no credential of that kind, and a wrong proof alike, and all three cost the
same work. A verification failure matches exactly one sentinel; an
infrastructure failure (a store outage, a store answering against its contract)
matches none, and the application answers it as a server error, never as a
failed sign-in. `store.ErrNotFound` from a method whose contract allows it
(`Take`, `Subject`, `RecordAssertion`, `MarkCloneSuspected`) is translated; from
one whose contract does not (a `List`) it passes through
wrapped, as an infrastructure failure.

**v2 exports no distinguishable not-found on any path that takes an
identifier.** If it did, someone would `errors.Is` on it and rebuild the oracle
in their handler.

**F-29 is closed by construction.** v2 has no identifier-first passkey sign-in:
`BeginPasskey` takes no identifier and answers everyone identically, and
`BeginSecondFactor` runs only for a subject the caller has already
authenticated. Nothing a stranger can submit reveals whether an account exists or
which credentials it holds, short of one residual a discoverable sign-in cannot
avoid: the lookup precedes the signature check, which needs the stored key, so a
stranger who already holds a user handle and a credential ID can confirm that
the pair is held (`ErrInvalidCredentials` rather than `ErrUnknownCredential`).
Random 64-byte handles make that useless without prior knowledge. A subject
imported from v1 keeps its v1 user ID as its handle (§9), which may be
guessable, so for those subjects the guarantee is weaker.

Two narrow, documented exceptions, both after a valid signature or on a path that
takes no identifier:

- `ErrUnknownCredential` (discoverable sign-in only): the presented credential
  maps to no subject. Its holder learns only that this RP has forgotten it,
  which is what WebAuthn Level 3's `PublicKeyCredential.signalUnknownCredential`
  acts on.
- `ErrCloneSuspected`: the signature was valid and the counter went backwards,
  or the credential is already marked and stays refused until the application
  clears the mark. It is a `*CloneSuspectedError` carrying the subject, so the
  application can tell the owner even after a discoverable sign-in.

An error's text names which check failed; it is for logs only, never for a
client. Timing is equalised by doing the real work, never by sleeping.

---

## 6. Packages in detail

### 6.1 `amr`: authentication methods and policy (G1)

A session records which methods proved it, as a set of RFC 8176 values plus any
the application defines. The library classifies the set; the application decides
which classifications may hold a session. The verdict is derived from the
methods every time it is needed, never stored: Kratos's GHSA-wc43-73w7-x2f5 was a
stored "available level" going stale.

The library issues or interprets `pwd`, `otp`, `hwk` (a WebAuthn assertion from a
credential that is not backup-eligible), `swk` (backup-eligible) and `mfa` (the
assertion itself verified the user). A `Policy` maps each method to a `Factor`
(class `Knowledge`, `Possession` or `Federated`, and whether it is
phishing-resistant); `Standard()` classifies the RFC values and the application
extends a copy with its own (a recovery code, an emailed code, a federated
login). `Satisfies(methods, requirement)` answers `AnyFactor`, `MultiFactor` or
`PhishingResistant`.

- A method absent from the policy counts for nothing, and so does an undefined
  requirement: unknown is never a pass.
- A first factor is a `Knowledge` or `Federated` method; multi-factor needs a
  first factor plus a `Possession` method, never two first factors: a password
  plus a federated login proves nothing about a device the user holds. Whether a
  federated login alone vouches for more is the application's call, outside
  `Satisfies`.
- `mfa` counts only beside `hwk` or `swk` from the same assertion: `{swk, mfa}`
  is multi-factor (a user-verifying authenticator is a multi-factor
  cryptographic authenticator in NIST SP 800-63B-4); `{mfa}` alone is nothing.
- `hwk` versus `swk` comes from the backup-eligibility flag the authenticator
  asserts. Neither says the key is hardware the verifier checked, so `amr` claims
  no AAL3; an attestation policy (later) can.
- Freshness is a separate question from strength: `Fresh(authTime, within, now)`
  answers "recent enough for a settings change". Kratos once conflated the two
  and it was a reported vulnerability.
- `Satisfies` is table-tested over every subset of the methods in the policy.

The method set holds only methods this application verified itself: a flat set
cannot say which assertion `mfa` came from, so an upstream identity provider's
`amr` claim never enters it; a federated sign-in is one application-defined
`Federated` method. The application persists the set as a JSON array on its
session row or in its token, beside the time of authentication.

### 6.2 `webauthn`: ceremonies (G1)

A thin, opinionated layer over `github.com/go-webauthn/webauthn`. go-webauthn
does the parsing and the cryptography; this package decides what is allowed,
binds every ceremony to its purpose, and owns the checks go-webauthn leaves to
its caller. The types and store interfaces are in the package's doc comments.

**Configuration.** `New` refuses a configuration where an origin's host is
neither the RP ID nor a subdomain of it, and an origin with a trailing slash, a
path or an uppercase host (never normalised). Origins are compared exactly and
are `https`, except `http://localhost` for development; the RP ID is never
derived from a request header and is fixed for the life of every credential.
Cross-origin iframes are refused (`topOrigin` present). Algorithms default to
EdDSA, ES256, RS256 (`-8, -7, -257`); the timeout defaults to five minutes, at
most fifteen. Attestation conveyance is `none`.

**Subjects and user handles.** The library never sees a user record: a ceremony
takes a `Subject` (the application's opaque key, a name a credential manager
shows, a display name). The user handle (`user.id`) is 64 bytes from
`crypto/rand`, created once per subject through `HandleStore.Ensure` and never
changed, and never the subject ID. Reusing it means a second registration on the
same authenticator replaces that authenticator's discoverable credential instead
of piling up a duplicate.

**Credential versions.** `Version` is the credential's schema version, set by the
library. Version 1 (`ImportedVersion`) marks a credential imported from v1,
whose backup flags were never recorded: its first assertion records the flags
instead of comparing them and moves it to the current version. The adoption has
one race: two concurrent assertions of a synced Version 1 credential (counter
0), both read before either writes, carrying valid signatures with different BE.
Both match the conditional update (`sign_count = 0` still holds), so the last
write's flags stand; an assertion that reads the credential after the first
write sees the current version and is refused on BE. Two valid signatures with
different flags need the credential's private key, so this is not an outside
attack; closing it would add a version condition to `RecordAssertion` and change
the store contract.

**Ceremonies.**

| Functions                                  | When                                                         | Options sent                                                                                                                                                                                                                                        | UV                                                                                |
| ------------------------------------------ | ------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `BeginRegistration` / `FinishRegistration` | an authenticated subject adds a credential                   | `excludeCredentials` = the subject's credentials; passkey: `residentKey: required`; security key: `residentKey: discouraged`, `hints: ["security-key"]`, `authenticatorAttachment: "cross-platform"`; optional `mediation: "conditional"` (passkey) | required for a passkey (preferred when conditional), preferred for a security key |
| `BeginPasskey` / `FinishPasskey`           | sign-in with no identifier                                   | no `allowCredentials`; usable with `mediation: "conditional"` (autofill) or modal                                                                                                                                                                   | required                                                                          |
| `BeginSecondFactor` / `FinishSecondFactor` | a subject the caller has already authenticated, or a step-up | `allowCredentials` = the subject's credentials                                                                                                                                                                                                      | preferred; the caller may require it                                              |

Every `Begin` writes one flow holding the ceremony kind, the caller's purpose
(`"login"`, `"stepup"`, …), the subject when known, the RP ID and the
go-webauthn session data, and returns options the browser's
`PublicKeyCredential.parseCreationOptionsFromJSON` /
`parseRequestOptionsFromJSON` accepts. Every `Finish` takes the flow (single
use), checks kind, purpose and subject against the caller's `Expect`, accepts
the browser's `toJSON()` output, refuses a response over 64 KiB unparsed, and
returns verified facts only: subject, credential ID, user verification, backup
flags, AAGUID, the `amr` methods and the time.

**Checks the package owns.** go-webauthn verifies the signature, the challenge,
`type`, the origin against the configured list, the RP ID hash and the flags it
is asked to require. This package adds, in order, each a test named for the
attack:

1. The flow exists, is unexpired and unconsumed (atomic `Take`), of the expected
   kind and purpose, and, when the ceremony names a subject, for that subject.
2. `topOrigin` absent.
3. User presence set, except for a conditional create (WebAuthn Level 3 §7.1
   verifies UP only when mediation is not conditional). User verification set
   when the ceremony requires it; a passkey sign-in without it is refused, never
   downgraded.
4. Registration: algorithm in the allow-list; credential ID absent for every
   subject (`Insert` → `ErrDuplicate`, which the application must not resolve
   by re-binding); BE=0 with BS=1 refused.
5. Discoverable assertion: the user handle is present (a response without one is
   malformed, `ErrInvalidCredentials`) and resolves to a subject; the credential
   ID is among that subject's credentials for this RP ID. Either miss is
   `ErrUnknownCredential`. The lookup runs only after the client data's type,
   challenge, origin, crossOrigin and topOrigin, the RP ID hash, UP and UV pass:
   a response failing one is `ErrInvalidCredentials` and reads neither store.
6. Second-factor assertion: the credential was listed in `allowCredentials` and
   is among the flow subject's credentials for this RP ID when `Finish` runs. A
   miss is `ErrInvalidCredentials`, never `ErrUnknownCredential`: the caller
   already knows the subject.
7. BE equals the stored value (it never changes; a change is refused and
   logged); BE=0 with BS=1 refused; a new BS is stored.
8. Counter: stored and received both 0 is normal (synced passkeys never count).
   Received greater than stored advances. Otherwise, with a non-zero stored
   counter, the credential is marked clone-suspected and the ceremony fails with
   `ErrCloneSuspected`. A credential already marked is refused with
   `ErrCloneSuspected` once its signature verifies, whatever its counter, with no
   new mark or recorded use, until the application clears the mark after the
   owner confirms, or deletes the credential. The error is a
   `*CloneSuspectedError` naming the subject and the credential, with `New` set
   when this ceremony set the mark. A canonical DER ECDSA signature is required.
9. `RecordAssertion` must apply; `applied=false` fails the ceremony. A failed
   write is never a pass.

**Not in G1.** An attestation policy (`direct`/`enterprise`, an AAGUID
allow-list, FIDO MDS3 the operator downloads under its own terms); an AAGUID
naming table (the community list carries no license, so the application supplies
names); a Related Origin Requests helper; PRF and largeBlob.

### 6.3 `hash`: password hashing (G3)

Modelled on Kratos's `hash/` package, which gets the shape right.

```go
type Hasher interface {
    Hash(ctx context.Context, password []byte) (string, error)
    Understands(encoded string) bool
}

// Verify walks a registry of comparators. Generation uses one algorithm;
// verification handles every format ever imported.
func Verify(ctx context.Context, password []byte, encoded string) (Result, error)

type Result struct {
    OK          bool
    NeedsRehash bool   // algorithm differs from policy, or parameters are below it
    NewEncoded  string // set iff OK && NeedsRehash, computed while the plaintext is in hand
}
```

- **bcrypt in G3; argon2id, the eventual default, later.** G3 ships `Verify`,
  the bounds, the limiter and a bcrypt `Hasher`, so `v2.0.0` verifies what v1
  hashed up to bcrypt cost 15 (§9). Every encoding carries its algorithm and
  parameters (bcrypt's `$2b$<cost>$`, PHC for the rest), so the column is `TEXT`.
- **`NeedsRehash` compares parameters, not only the algorithm.** Kratos's
  `Understands` is true for any argon2id hash regardless of cost, so it rehashes
  on an algorithm change but not on a cost increase; `Params(encoded)` closes
  that.
- **Rehash is reported, never performed.** `NewEncoded` is computed eagerly
  because the plaintext exists only during `Verify`; the application writes it
  if it wants to. Failure to write must never deny a user who proved their
  password.
- **Parameter bounds are mandatory.** Cost parameters live inside the stored
  string, so a hostile or corrupted row is an out-of-memory primitive
  (`m=16777216` is 16 GiB per verification). Kratos's bounds apply, each
  algorithm's with its importer: argon2 memory ≤ 1 GiB, iterations ≤ 10,
  parallelism ≤ 16; bcrypt cost ≤ 15; scrypt N ≤ 2^17, r ≤ 8, p ≤ 10; pbkdf2
  iterations ≤ 10^7. `ValidateImported(encoded)` refuses a bad hash before a
  bulk import persists it; `Verify` applies the same bounds.
- **A concurrency limiter**, which Kratos lacks: a buffered channel of size N
  (default `GOMAXPROCS`) acquired with a `select` on `ctx.Done()`, and
  `ctx.Err()` checked immediately before the KDF call, so a client that hung up
  while queued costs no KDF run.
- **argon2id's `p` is a fixed constant**, not `runtime.NumCPU()`, so hashes do
  not differ across a fleet.
- **The bcrypt hasher refuses input over 72 bytes** with a named error rather
  than truncating (F-10). The policy is per hasher: argon2id has no such limit.

### 6.4 `token`: opaque secrets (G3)

One primitive behind password reset, email verification and invitations: mint a
256-bit `crypto/rand` value, return the plaintext exactly once, hand the store
only a digest (F-05).

- **HMAC, not a bare hash**, keyed by a rotation list `[][32]byte`: sign with
  `[0]`, verify against each in turn, so a store leak alone does not permit
  precomputation. A password hash is the wrong tool: these are high-entropy
  server-generated values, and a per-attempt KDF is a DoS lever.
- **A greppable prefix** on the plaintext (`ga_rst_`, `ga_vrf_`), so secret
  scanners and log redaction can match it.

### 6.5 `oidcrp`: relying party (G3)

`HandleCallback` returns **verified claims**. It does not look up a user, does
not create one, and does not know what a user is, which makes F-01
inexpressible.

```go
type Verified struct {
    Issuer        string
    Subject       string         // never empty; required by OIDC Core §2
    Email         string
    EmailVerified bool
    Claims        map[string]any // allow-listed
    AMR           []string       // upstream, only if the provider is configured as trusted
    ACR           string
}
```

- **Mandatory, not opt-in:** the state bound to the browser that started the
  flow (a cookie the callback checks, so an attacker's own valid state cannot
  complete in a victim's browser: login CSRF); PKCE S256; a nonce compared in
  constant time; `azp` equal to the client ID whenever it is present, at any
  audience count, and required on a multi-audience token (a `null`, non-string
  or empty `azp` counts as missing, so it cannot disarm the rule); `sub`
  required; `email_verified: false` refused; an outbound client from `httpx`.
- **`ProviderResolver`** replaces v1's boot-time static map:
  `Resolve(ctx, id) (Provider, error)`, answered from a config file or a
  per-tenant row, which makes bring-your-own-connection expressible.
- **Sealed flow state.** The state parameter carries the flow ID, provider ID
  and PKCE verifier inside an XChaCha20-Poly1305 sealed blob with a key rotation
  list; store-backed single use (`FlowStore.Take`) is the default.
- **Provider-asserted MFA fails closed.** `TrustedAAL2ACR` and `TrustedAAL2AMR`
  per provider, empty by default, so an upstream `acr` is never a second factor
  unless explicitly enumerated.
- **An outbound parameter allow-list.**
- **The library never links accounts.** Where v1 had `LinkPolicy`, v2 returns a
  `LinkProposal` the application acts on, and by default an assertion matching
  an existing address proves nothing.

### 6.6 `attempt`: failed-attempt budgets (G2)

```go
type Counter interface {
    Incr(ctx context.Context, key string, window time.Duration) (n int, err error)
    Reset(ctx context.Context, key string) error
}
```

The count is incremented before validating, in its own transaction, so a
rollback cannot undo it. The policy (how many, how long) stays with
the application; the library supplies the mechanism and the uniform-response
discipline.

### 6.7 `normalize`: identifier normalisation (later)

PRECIS profiles for email and phone, ported from Kratos's `x/normalize.go`,
closing the homoglyph and zero-width-joiner duplicate-account attack. Strict at
registration, graceful at lookup, and the graceful path re-runs the whole
pipeline after stripping forbidden runes.

### 6.8 `audit` (G3)

The event vocabulary, a `Logger` interface and a `log/slog` adapter. Events are
emitted **from the primitives**; there are no wrappers (F-22, F-34).

- **Who supplies what.** A primitive emits what only it knows (method, subject
  ID, credential ID, outcome) with the caller's `ctx`. Request facts (IP
  address, user agent, request ID) are put on `ctx` by the application's own
  middleware and added by its `Logger`, so no primitive sees an `http.Request`.
- **Personal data.** Events carry typed fields only, never a free-form map, and
  no credential material. The subject is the pseudonymous subject ID; the
  vocabulary has no email, username or IP field. The adapter wraps a
  `*slog.Logger` the application builds, so `slog.HandlerOptions.ReplaceAttr`
  redacts whatever the application adds.
- **Wiring.** G3 adds emission to the G1 and G2 packages. The `Logger` arrives
  as a new configuration field or per call beside the stores, never as a method
  on a published interface (§4.2 rule 5), and ships in a prerelease before
  `v2.0.0` freezes the API.

### 6.9 `httpmw`: credential extraction middleware (G3)

Reads a credential the application issued from the request, verifies it with
`jwtx` or `session`, and puts the verified fact on the request context. It
serves no ceremony.

- **Reading.** Cookie and bearer-header extractors and an ordered combination of
  them; the verified fact is set and read through typed functions with an
  unexported context key, never a string key.
- **Writing.** A session cookie writer for the sign-in and sign-out handlers:
  `Secure` and `HttpOnly` forced, the `__Host-` prefix validated, and a clear
  that repeats every attribute so sign-out removes the cookie it set.
- **An access token only:** verification asks `jwtx` for an access token rather
  than checking the type afterwards, so a refresh token is refused (F-02).
- Every extraction and verification failure is the same unauthorized error: a
  malformed header, a wrong scheme, a missing or empty cookie and a bad token are
  indistinguishable, and an empty cookie never reaches a store.
- It authenticates an existing session and never creates or rotates one; the
  sign-in handler rotates (F-14).
- A missing verifier is a construction error, never a pass: one constructor that
  returns an error, no panicking variant.
- The application owns the error response and authorization; the middleware
  reports unauthorized. v1's `ErrorHandler`, `DefaultErrorHandler` and
  `ErrForbidden` are not carried.

---

## 7. Batteries, deferred

Batteries would compose primitives into working flows. That convenience is
exactly what produced F-01, F-11, F-12, F-15, F-29, F-30 and F-35, so v2 ships
building blocks and a runnable example (`examples/passkeys`) instead. Batteries
come when a second application needs the same flow, and must clear four bars:

1. **No fail-open on wiring the library cannot verify** (F-35). Every battery
   dependency is a constructor argument validated at construction, with no
   nil-tolerant field and no zero-value-usable type. A battery that cannot
   answer a question refuses.
2. **The default never decides security.** No enum whose wrong value is a
   bypass; two behaviours that genuinely differ are two constructors with names
   you have to type.
3. **No accreted identity decisions** (F-01 began as a convenience).
   `batteries/` may not import a user store; it takes application callbacks and
   returns decisions.
4. **No blinded observability** (F-22, F-34). No decorators: primitives emit,
   batteries pass a logger through.

---

## 8. Testing

Every fix ships with a test that fails when the fix is reverted; tests are named
for the attack and cite the RFC or CVE class; adversarial suites per package
mirror the defect classes; a weekly mutation run reports how
hard the suite bites; fuzz targets cover every parser reachable with
attacker-controlled bytes. Vulnerability reproductions are tests in the package,
never standalone programs, which rot and ship in the module zip.

**Conformance suites the application runs against its own store.** `authtest`
is an importable package. `FlowStoreSuite` and `WebAuthnStoreSuite` cover what
an application otherwise gets wrong: `Take` and `Ensure` race N goroutines and
exactly one wins (or all agree); a credential ID held by one subject cannot be
inserted for another; `RecordAssertion` loses cleanly to a concurrent update;
expiry is enforced on read, not by a sweeper; every exported field round-trips,
and so does a credential as a registration stores it; not-found is never
confused with success; `ErrDuplicate` means the credential ID is held and
nothing else; handles compare as bytes, never as text under a collation. The
races prove atomicity only when their callers hold separate database connections
at once, so each store the harness builds opens its pool's connections first.

**A virtual authenticator.** `authtest.NewAuthenticator` (ES256 and Ed25519,
attestation `none`, settable flags and counters, and hooks that forge a wrong
origin, RP ID hash, challenge or type) gives every check in §6.2 a test that
produces the attack, not a mock that pretends to. A real browser drives the
example in CI, because only a browser shows that what `toJSON()` sends is what
the library accepts, and the suites run against a reference SQLite store
(`examples/sqlitestore`).

---

## 9. Compatibility with v1

v2 is a new import path, so nothing breaks by upgrading: a consumer moves when it
chooses. v1.x receives security fixes for twelve months from the `v2.0.0`
release, with the end date stated in `SECURITY.md`.

- `UserStore` is gone. The application already has a user table; it uses it
  directly and calls the library for verification only.
- WebAuthn credentials registered by v1 carry over as second factors. A v1
  credential's user handle is the subject ID, so the application seeds its
  `HandleStore` with that value for those subjects before any `Begin` runs for
  them; `BeginRegistration` and `BeginSecondFactor` call `Ensure`, which stores a
  fresh random handle for a subject that has none, permanently, so either one
  before seeding strands the v1 handle. Their backup flags move from v1's
  metadata keys into the typed fields; a credential whose flags were never
  recorded is imported as Version 1 and takes them from its next assertion
  (§6.2). That handle may be guessable (§5).
- Password digests carry forward unchanged: `hash` verifies bcrypt and reports
  `NeedsRehash` when a digest's cost is below policy; once argon2id lands, the
  same signal moves a deployment to it on next sign-in. One break: v1 accepted
  bcrypt cost up to 31, and v2 refuses a digest above 15 (§6.3), because a
  stored cost is a CPU-exhaustion lever. A deployment that hashed above 15
  rehashes at 15 or lower before it moves.
- TOTP `$gat1$` secrets and `$gab1$`/`$gab2$` recovery digests stay verifiable in
  G2, with golden vectors.
- Reset and verification token digests carry forward, but the HMAC keying is new,
  so live tokens are invalidated. Their TTLs are one and twenty-four hours; the
  window closes on its own.
- `middleware` maps to `httpmw`, and `session.SessionTokenLocation` to its
  extractors and cookie writer; `audit.AuditLogger` and `StdLogger` map to
  `audit`'s `Logger` and its `log/slog` adapter. v1's configurable redaction
  becomes a vocabulary without personal fields plus `ReplaceAttr`.
- `middleware.BasicAuthMiddleware`, the vendor provider constructors and the
  audit wrappers have no replacement; the migration guide names what to write
  instead.

**Parity.** Each G2 and G3 design pass starts from v1's exported API in its area
(`git show origin/v1:<package>`) and carries a symbol-by-symbol table mapping
each symbol to its v2 home or to a removal in §3. G3 does not exit until the
tables cover every non-test file of v1.

---

## 10. Decisions

1. **The library never owns identity.** No `UserStore`, no lookup, no
   provisioning, no linking. Every v1 finding that could not be fixed in place
   sat on the wrong side of that line (§1).
2. **Typed stores for durable credentials; one opaque, single-use `FlowStore`
   for ceremony state** (§4, FAQ).
3. **Stores are passed per call, every atomic invariant is a named store
   method, the suite round-trips every field, and a published interface never
   gains a method.** The application owns its transactions, and the contract
   stays checkable as it grows (§4.2).
4. **A passkey counts as two factors only with user verification.** NIST SP
   800-63B-4 treats a user-verifying authenticator as a multi-factor
   cryptographic authenticator. Kratos counts a passkey as one factor (it
   reverted counting it as two, #3853); here the rule is explicit and tested
   (§6.1).
5. **Passkey sign-in is discoverable only.** No identifier-first flow and no
   `allowCredentials` before the subject is authenticated, which removes the
   enumeration question instead of mitigating it (§5).
6. **No ceremony HTTP handlers in the core.** Building blocks and a runnable
   example; batteries deferred until a second application needs a flow (§7).
   `httpmw` reads and writes credentials around the application's handlers and
   serves no ceremony, so it is in the core.
7. **One module, with the boundary enforced by `depguard`.** See the FAQ.
8. **`go-webauthn/webauthn`, pinned exactly; its checks are kept here too.** It
   is effectively single-maintainer, so every bump reads its changelog and runs
   the full suite, and the §6.2 checks stay in this package even where
   go-webauthn also performs them. Go 1.26 is the floor because go-webauthn
   v0.18 requires it. JSON goes through the standard library's `encoding/json`,
   because go-webauthn's options rely on its `omitzero`.
9. **v2 is built on a `v2` branch until `v2.0.0`**, so `main` never offers less
   than v1 did; branches and releases are in `docs/ci.md`.
10. **`hash` ships bcrypt in G3**, so `v2.0.0` verifies every kind of credential
    v1 did (§6.3, FAQ).
11. **`httpmw` and `audit` are in G3**, so `v2.0.0` replaces v1 except the
    removals in §3.
12. **No OIDC provider in this module; go-auth is a relying party.** An identity
    provider issues tokens about users, which is identity on the other side of
    the line, and building one is the highest-risk option: an extra-large
    effort with its own certification, CVE stream and maintenance burden, where
    Ory Hydra (an OpenID Certified provider) and zitadel/oidc (a certified
    relying party with provider support) exist. If demand
    appears, it is a separate, opt-in module over zitadel/oidc, never the core.
13. **Prereleases may change the API; `v2.0.0` freezes it** under §4.2 rule 5.
    A break is declared with `!` in the pull request title.
14. **Attestation `none` in G1.** The AAGUID is kept for naming only; an
    attestation policy, and any AAL3 claim, come later.
15. **Login CSRF is closed by construction.** `oidcrp` binds every flow's state
    to the browser that started it, with no opt-out: v1 offered the binding
    opt-in and left its unbound entry points exposed (F-16), and a sealed,
    single-use state alone does not stop an attacker's own state completing in
    a victim's browser.

---

## 11. FAQ

**Why typed stores, not opaque records?** An earlier draft proposed opaque,
versioned records for every credential kind, so that a store could not drop a
field it did not know. Typed won because:

- **The application owns its data.** Typed columns can be queried, indexed,
  cascaded on account deletion, scrubbed column by column and reported on
  ("which members of this tenant lack a phishing-resistant method" is one query,
  not a decode of every member's records).
- **No lock-in.** Leaving the library leaves ordinary columns, not a
  library-specific encoding, and an existing schema adopts v2 without a data
  migration.
- **Atomic updates stay narrow.** A counter update is one conditional `UPDATE`
  on one column; a rename and a sign-in never conflict. Opaque records make every
  change a whole-record compare-and-swap.
- **Opaque records cannot express what WebAuthn needs** without growing a
  revision and declared unique lookup keys: refusing a credential ID another
  subject holds and finding a subject by user handle are cross-record lookups.

What it costs, and what pays for it: a store can drop a field again (§4.2 rule
4 catches it in CI, rule 3 refuses the security-critical ones at run time);
adding a field no longer comes free (structs may grow, interfaces may not);
atomicity lives in the application's SQL (rule 2 names every such operation and
`authtest` races it); each application writes more store code per kind (a
reference SQL store can absorb that once a second consumer exists). Ceremony
state stays opaque because nothing about it needs querying, it lives minutes,
and only the library reads it.

**Why one module, not two?** Shipping `batteries/` as its own module would make
the boundary a hard dependency fact and let a batteries defect avoid forcing a
core release. It also doubles the release train, needs `replace` directives
throughout development and complicates release-please: real costs for a
solo-maintained library. A `depguard` rule gives the same guarantee at CI.

**Why bcrypt before argon2id?** `v2.0.0` must verify every digest v1 stored, and
v1 stored bcrypt. argon2id generation and the other importers need their own
bounds and parameter policy, so they get a design pass of their own; until then
`NeedsRehash` compares a bcrypt digest's cost with policy.

**Why not an OIDC server?** Decision 12.

---

## 12. Lessons from the v1 audit

The v1 audit registered 35 findings: 23 in the original review of v1.1.1, six
more from writing the missing WebAuthn tests, and five from two independent
adversarial reviews of the fix work itself, plus the half-wired MFA gate found
after release. A G1 row is a shipped rule; a G2 or G3 row is a rule that phase's
section here already decides, or the v1 fix it keeps, because `v2.0.0` replaces
v1 (decision 11). Strengthening a kept fix is that phase's design decision. The
full register, with each finding's proof, fix and consumer notes, is [on the
`v1`
branch](https://github.com/meysam81/go-auth/blob/v1/docs/security-hardening.md).

| Finding                | What went wrong in v1                                                                                     | In v2                                                                                                                                                        |
| ---------------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| F-01                   | OIDC identity assigned from an unverified email claim (the CVE-2023-28131 class)                          | G3 `oidcrp` returns verified claims and never looks up, links or creates a user; `email_verified: false` refused (§6.5)                                      |
| F-02                   | a refresh token authenticated as an access token                                                          | verification asks for one token type; `httpmw` accepts access tokens only                                                                                    |
| F-03, F-04             | issuer and audience minted but never verified; RS256 and ES256 documented but unusable                    | G3 `jwtx` keeps v1's fix: the signing method pinned, `iss` and `aud` verified when configured, and the key and algorithm paired at construction              |
| F-05, F-06             | reset and verification tokens, TOTP secrets and backup codes stored in replayable form                    | G3 `token` hands a store only an HMAC digest (§6.4); G2 `recovery` keeps keyed digests; G2 `totp` keeps v1's sealing of a secret when a cipher is configured |
| F-07                   | TOTP enrolment armed before the user proved possession                                                    | G2 `totp` keeps v1's fix: a secret stays pending until confirmed with a valid code                                                                           |
| F-08, F-31             | a TOTP code replayed inside its window, including by adding a space                                       | G2 `totp`: a durable replay guard (§2), keyed on exactly the value the validator compares                                                                    |
| F-09, F-29             | account existence leaked by sign-in timing and by `BeginLogin`                                            | one sentinel and the same work on every path; passkey sign-in is discoverable only (§5)                                                                      |
| F-10                   | passwords over 72 bytes silently truncated                                                                | the bcrypt hasher refuses over-length input                                                                                                                  |
| F-11, F-12, F-26       | a swallowed rollback failure, a reset token left live, a counter write failure printed and swallowed      | `errcheck` with `check-blank`; a failed write is never a pass; atomic named store methods                                                                    |
| F-13, F-14             | credential changes revoked nothing; session identifiers never rotated                                     | stores per call, so revocation commits with the change; `session` rotates, revokes every session of a subject and keeps refresh families                     |
| F-15                   | HTTP Basic middleware ran bcrypt on every request with no path to a second factor                         | removed (§3)                                                                                                                                                 |
| F-16, F-17, F-18, F-19 | OIDC state unbound to the browser; no PKCE; no nonce; `azp` unchecked on multi-audience tokens            | G3 `oidcrp`: all mandatory, the browser binding included (§6.5, decision 15)                                                                                 |
| F-20                   | discovery and token exchange on an unbounded default client                                               | G3 `httpx` keeps v1's bounded client (a timeout and a response-size cap) and refuses non-public addresses (§2)                                               |
| F-21                   | identity provider claims copied into the application's own JWT                                            | claims are allow-listed; an upstream `amr` never enters the method set                                                                                       |
| F-22, F-34             | hand-mirrored audit decorators missed new methods, then recorded every refresh and revocation anonymously | primitives emit their own events; no wrappers                                                                                                                |
| F-23                   | untested code in the paths that mattered; the linter ran on defaults                                      | `.golangci.yml`; coverage floors that only rise and refuse an unlisted package; fuzz targets; revert-the-fix tests                                           |
| F-24                   | a 300-nanosecond challenge TTL: an untyped `300` passed as a `time.Duration`                              | G1: the ceremony timeout is a bounded `time.Duration` (`Config.Timeout`, 30 s to 15 min)                                                                     |
| F-25, F-28             | a cloned authenticator was undetectable; Level 3 backup flags were not persisted                          | typed credential fields, a conditional counter update and a clone mark (§6.2)                                                                                |
| F-27                   | WebAuthn ceremonies and OIDC flows shared one state namespace                                             | `Flow.Kind`, purpose and subject are checked on every `Take`                                                                                                 |
| F-30                   | `NewMicrosoftProvider` disabled ID token issuer verification                                              | no vendor constructors; discovery from an issuer URL (§3)                                                                                                    |
| F-32                   | a store that dropped a new control field was read as "no such control" and the flow proceeded             | a missing field fails closed (§4.2 rule 3); `authtest` round-trips every exported field                                                                      |
| F-33                   | the TOTP payload tag sat outside everything that authenticated it                                         | G2 `totp` keeps v1's fix: a sealed secret carries its state tag and a digest of its subject inside the ciphertext                                            |
| F-35                   | a half-wired `Authenticator` let the password alone pass MFA                                              | no security answer from optional wiring; enrolment is read from the store (§1)                                                                               |

Three of the fix-work defects share one shape: a control whose input can go
missing must refuse, not proceed. A mutation gate proves a fix is load-bearing,
not that it is correct; the replay bypass (F-31) survived revert-the-fix testing
because the fix was present, keyed on the wrong value. A security change
therefore also gets an adversarial review that attacks the fix itself.
