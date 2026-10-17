# go-auth v2 — design

Status: proposed. Phase G1 (`amr`, `webauthn`, `store`, `authtest`) is approved
for implementation; G2 and G3 each get a design pass of their own before code
(§11). Baseline: `v1.1.3`. Module becomes `github.com/meysam81/go-auth/v2`. Go
1.26 or newer.

v1 was an audit and a repair. v2 is the shape the repairs kept pointing at. This
document is the design; `docs/v2-plan.md` will be the execution plan.

---

## 1. The line

> **The library verifies credentials and emits verified facts. It never creates,
> mutates, or owns identity.**

This is not a slogan; it is a testable structural property, and v1 produced the
evidence for it. Of the 35 findings in `docs/security-hardening.md`, the
primitives produced more in raw count — 21 against 12 — but every one of them was
fixable inside its own mechanism: add PKCE, pin the token type, hash the token
before it reaches the store. The findings that could **not** be fixed inside v1
were all four of the ones where a component owned an identity decision or wired
two others together:

| Finding                              | Why it could not be fixed in v1                                                       |
| ------------------------------------ | ------------------------------------------------------------------------------------- |
| F-15 `BasicAuthMiddleware`           | bcrypt per request and no path to a second factor; only removal fixes it              |
| F-29 `BeginLogin` enumeration oracle | closing it changes what existing callers are told                                     |
| F-30 `NewMicrosoftProvider`          | a vendor convenience constructor that must disable issuer verification to work at all |
| F-35 half-wired MFA gate             | fixed only by removing the dependency on wiring, not by validating it                 |

F-35 is the one to keep in view, because it shipped in a release and needed no
attacker sophistication at all. `IsTOTPEnabled` answered `(false, nil)` when the
`Authenticator` held no `totp.Manager`; the MFA gate read that as "no factor
enrolled"; the password alone returned the user while the store said the factor
was armed. The rule it establishes governs this whole design:

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
an existing human. Decides tenancy. Decides whether to provision on first sight.
Decides which method sets may hold a session. Sends email. Enforces RBAC.
Persists everything, in its own schema, inside its own transactions.

---

## 2. Module and package layout

One module, `github.com/meysam81/go-auth/v2`, with the boundary enforced by the
linter rather than by convention. The module lives at the repository root on
`main` (the major-branch layout); v1 moves to a `v1` branch (§11). The phase
column is the delivery order.

```
(repository root)
  amr/          authentication methods (RFC 8176), factor classes, policy        G1
  webauthn/     registration, second-factor and passkey ceremonies              G1
  store/        the single-use FlowStore and the shared error sentinels         G1
  authtest/     conformance suites and a virtual authenticator                  G1
  challenge/    typed hand-off token, durable challenge state, step-up          G2
  attempt/      failed-attempt budgets                                          G2
  totp/         RFC 6238 enrolment and validation, durable replay guard         G2
  recovery/     recovery codes: generation, keyed digests, legacy verifiers     G2
  token/        opaque secret mint / digest / verify (reset, verification)      G3
  session/      session identifiers, rotation, refresh families                 G3
  oidcrp/       OIDC relying party: handshake in, verified claims out           G3
  httpx/        outbound transport that refuses non-public addresses            G3
  jwtx/         JWT mint and verify                                             G3
  hash/         password hashing: pluggable, PHC-encoded, parameter-bounded     later
  normalize/    PRECIS identifier normalisation                                 later
  audit/        event vocabulary and a Logger interface. Nothing else.          later
  httpmw/       credential extraction middleware                                later
  batteries/    optional wired-up flows; deferred (§7)                          —
```

**Why one module and not two.** Shipping `batteries/` as a separate Go module
would make the boundary a hard dependency fact and let a batteries defect avoid
forcing a core release. It also doubles the release train, needs `replace`
directives throughout development, and complicates release-please — real costs
for a solo-maintained library. The same guarantee is available for less: a
`depguard` rule that forbids any core package from importing `batteries/`, and
forbids `batteries/` from importing anything the core does not already depend on.
The linter enforces at CI what a module boundary would enforce at build.

**Enforced by `.golangci.yml`, not by discipline:**

- No core package may import `batteries/`.
- No core package may declare or consume a user-store interface. There is no
  `UserStore` in v2.
- Every package declares the narrow store interface it calls, beside the code
  that calls it. There is no shared "storage" super-interface.
- The direct-dependency allow-list: `go-webauthn/webauthn` (pinned exactly,
  §11), `pquerna/otp`, `golang-jwt/jwt/v5`, `coreos/go-oidc/v3`, `x/crypto`,
  `x/oauth2`. Anything else needs a design note.

---

## 3. What v2 removes

The v1 register's §4.1 listed these; here they are with the reason restated
against the line.

| Removed                                 | v1 lines | Reason                                                                                                                                                                                                                                                                                                                                        |
| --------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `provider/*` vendor constructors        | ~1,264   | Configuration, not logic. OIDC discovery reaches every OIDC-capable provider from an issuer URL. They were 0%-covered in v1 and one of them (F-30) had to disable issuer verification to work. Replaced by `oidcrp.NewOIDC(issuer, …)` plus documented recipes.                                                                               |
| `audit/wrapper.go`                      | ~652     | 19 hand-mirrored decorators. F-22 and F-34 are the same defect twice. Replaced by events emitted from the primitives.                                                                                                                                                                                                                         |
| `storage/memory.go` from the public API | ~913     | Ships an in-memory identity store as public API. Becomes `authtest`, a conformance harness.                                                                                                                                                                                                                                                   |
| `middleware/basic.go`                   | ~123     | F-15.                                                                                                                                                                                                                                                                                                                                         |
| `storage.UserStore`                     | —        | The coupling that made F-01 and F-35 expressible.                                                                                                                                                                                                                                                                                             |
| `basic.Authenticator`'s user CRUD       | —        | The library hashes and verifies; it does not own the row.                                                                                                                                                                                                                                                                                     |
| `oidc.findOrCreateUser`                 | —        | F-01. Replaced by returning claims.                                                                                                                                                                                                                                                                                                           |
| `auth/webauthn` as written              | ~802     | The user handle is the application's user ID (the spec wants random bytes with no meaning); login is user-ID-first only, which is the F-29 oracle; no `excludeCredentials`; the counter is written blind, so concurrent assertions both pass the rollback check; backup flags live in an untyped metadata map. Replaced by `webauthn` (§5.4). |

The `Enrollment`/`LookupEnrollment` shape added in v1.1.3 for F-35 survives into
v2 as the general pattern, not as a special case: enrolment state is read from
the store, never inferred from which objects the caller happened to construct.

---

## 4. The storage contract

The library keeps two kinds of state, and they get two different contracts.

- **Durable credentials the application keeps and administers**: WebAuthn
  credentials and user handles in G1; TOTP secrets and recovery codes in G2.
  These are **typed**. Each package declares the narrow interface it calls; the
  application maps it onto its own tables and columns.
- **Short-lived ceremony state only the library reads**: the WebAuthn challenge
  and its session data, the OIDC handshake, a challenge in flight. This is
  **opaque**, held in one single-use `FlowStore`.

### 4.1 `FlowStore`

```go
package store

// Flow is ceremony state the application persists without interpreting.
type Flow struct {
    Kind      string    // which ceremony wrote it; the reader checks it
    Payload   []byte    // library-owned encoding
    ExpiresAt time.Time // the store refuses to return an expired flow
}

type FlowStore interface {
    Put(ctx context.Context, id string, f Flow) error

    // Take fetches and consumes atomically. It MUST NOT be a Get followed by a
    // Delete: on a READ COMMITTED database two concurrent callers would both
    // observe the flow unused and both succeed. The SQL shape is
    //   UPDATE flows SET used_at = ? WHERE id = ? AND used_at IS NULL AND expires_at > ?
    // checking the affected-row count. Returning ErrNotFound for missing,
    // expired and already-consumed alike is required: the difference is an oracle.
    Take(ctx context.Context, id string) (Flow, error)
}
```

Flow IDs are 256-bit `crypto/rand` values. A flow is never extended or
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
   takes its store as an argument:
   `webauthn.FinishRegistration(ctx, flows, creds, …)`. The application passes
   a value bound to its own transaction, so a new credential, the sessions it
   revokes, the audit row and the outbound notice commit together or not at
   all. The library never opens, commits or assumes a transaction.
2. **Every invariant that needs atomicity is one named store method, and the
   library calls it itself.** Its contract states the SQL shape and the
   concurrency guarantee; the application never has to remember to enforce it.
   G1's atomic operations: `FlowStore.Take`, `CredentialStore.Insert` (credential
   ID unique across every subject), `CredentialStore.RecordAssertion`
   (conditional on the stored counter), `HandleStore.Ensure`
   (create-if-absent).
3. **A field the library needs is never answered by its zero value.** A loaded
   credential with an empty ID, public key, RP ID, a zero `CreatedAt` or a zero
   `Version` is refused as a store fault (fail closed). Booleans cannot be
   checked this way, which is what rule 4 is for.
4. **The conformance suite round-trips every exported field.** `authtest` fills
   each exported field of every stored struct with a distinct non-zero value by
   reflection and requires deep equality on the way back. A field added in a
   later release therefore fails the application's CI until its store persists
   it. This is the answer to F-32 (a documented field the store never wrote,
   certified by a suite that asserted the wrong thing), without making the data
   opaque.
5. **A published interface never gains a method.** A new capability is a new
   interface, detected with a type assertion and documented as optional. A
   struct may gain fields (rule 4 catches stores that drop them).
6. **Not-found is a store concern.** Stores return `store.ErrNotFound`; the
   authentication functions never surface it (§6).

### 4.3 Why typed, not opaque records (decision, 2026-10-17)

The earlier draft of this section proposed opaque, versioned records for every
credential kind, so that a store could not drop a field it did not know. It was
replaced because:

- **The application owns its data.** Typed columns can be queried, indexed,
  cascaded on account deletion, scrubbed column by column and reported on ("which
  members of this tenant lack a phishing-resistant method" is one query, not a
  decode of every member's records).
- **No lock-in.** Leaving the library leaves ordinary columns, not a
  library-specific encoding someone has to decode forever, and an existing
  schema adopts v2 without a data migration.
- **Atomic updates stay narrow.** A counter update is one conditional `UPDATE`
  on one column; a rename and a sign-in never conflict. Opaque records make every
  change a whole-record compare-and-swap.
- **Opaque records could not express what WebAuthn needs** without growing a
  revision and declared unique lookup keys: refusing a credential ID that
  another subject holds and finding a subject by user handle are both
  cross-record lookups.

What that costs, and what pays for it: the store can drop a field again (rule 4
catches it in CI; rule 3 refuses the security-critical ones at run time); adding
a field no longer comes free (structs may grow, interfaces may not: rule 5);
atomicity now lives in the application's SQL (rule 2 names every such operation
and `authtest` races it); each application writes more store code per kind (a
reference SQL store can absorb that once a second consumer exists).

Ceremony state keeps the opaque model because nothing about it needs querying,
it lives minutes, and only the library ever reads it.

---

## 5. Primitives

### 5.1 `hash` — password hashing (later)

Modelled on Kratos's `hash/` package, which gets the shape right.

```go
type Hasher interface {
    Hash(ctx context.Context, password []byte) (string, error)
    Understands(encoded string) bool
}

// Verify walks a registry of comparators. Generation uses ONE algorithm; verification
// must handle every format ever imported. That asymmetry is deliberate.
func Verify(ctx context.Context, password []byte, encoded string) (Result, error)

type Result struct {
    OK          bool
    NeedsRehash bool   // algorithm differs from policy, OR parameters are below it
    NewEncoded  string // populated iff OK && NeedsRehash — computed while the plaintext is in hand
}
```

Decisions:

- **argon2id default**, bcrypt retained for verification and available for
  generation. PHC-style encoding carries algorithm and every parameter, so the
  application's column is `TEXT` and nothing else.
- **`NeedsRehash` compares parameters, not just the algorithm prefix.** Kratos's
  `Understands` returns true for any argon2id hash regardless of cost, so it
  rehashes on algorithm change but not on a cost increase. That is a gap; we
  close it by exposing `Params(encoded) (Params, error)` and comparing.
- **Rehash is reported, never performed.** The library has no store. `NewEncoded`
  is computed eagerly because the plaintext exists only during `Verify`, and the
  application writes it if it wants to. Failure to write must never deny a user
  who proved their password.
- **Parameter bounds are mandatory.** Cost parameters live _inside the stored
  string_, so a hostile or corrupted row is an OOM primitive: `m=16777216` is 16
  GiB per verification. Port Kratos's `hash_limits.go` bounds wholesale
  (argon2 memory ≤ 1 GiB, iterations ≤ 10, parallelism ≤ 16; bcrypt cost ≤ 15;
  scrypt N ≤ 2^17, r ≤ 8, p ≤ 10; pbkdf2 iterations ≤ 10^7) and export
  `ValidateImported(encoded string) error` for bulk-import paths, so a bad hash is
  refused before it is persisted rather than crashing every later sign-in.
- **A concurrency limiter, which Kratos does not have.** A buffered channel of
  size N inside the verifier, acquired with a `select` on `ctx.Done()`. Default
  N = `GOMAXPROCS`, configurable.
- **`ctx.Err()` checked immediately before the KDF call**, so a client that hung
  up while queued does not cost 128 MiB.
- **`p` is a fixed constant, not `runtime.NumCPU()`**, so hashes do not differ
  across a fleet.
- **72-byte handling.** The bcrypt hasher refuses over-length input with a named
  error rather than truncating (v1's F-10). argon2id has no such limit; the policy
  is per-hasher, not global.

### 5.2 `token` — opaque secrets (G3)

One primitive behind password reset, email verification and invitations. Mint a
256-bit `crypto/rand` value, return the plaintext exactly once, hand the store
only a digest. v1 proved this out under F-05; v2 generalises it and adds two
things from Kratos:

- **HMAC, not a bare hash**, keyed by a rotation list `[][32]byte` — sign with
  `[0]`, verify against each in turn. A store leak alone then does not permit
  precomputation. A password hash is the wrong tool: these are high-entropy
  server-generated values, and a per-attempt KDF is a DoS lever.
- **A greppable prefix** on the plaintext (`ga_rst_`, `ga_vrf_`), so secret
  scanners and log redaction can match it.

### 5.3 `amr` — authentication methods and policy (G1)

A session records which methods proved it, as a set of RFC 8176 values plus any
the application defines. The library classifies the set; the application decides
which classifications may hold a session. Kratos's lesson applies unchanged: the
verdict is derived from the methods every time it is needed, never stored
(GHSA-wc43-73w7-x2f5 was a stored "available level" going stale).

```go
package amr

type Method string

// RFC 8176 values the library issues or interprets.
const (
    PWD Method = "pwd" // password
    OTP Method = "otp" // one-time password (RFC 4226/6238)
    HWK Method = "hwk" // WebAuthn assertion, credential not backup-eligible (BE=0)
    SWK Method = "swk" // WebAuthn assertion, backup-eligible credential (BE=1)
    MFA Method = "mfa" // the WebAuthn assertion itself verified the user (UV=1)
)

type Class uint8

const (
    Unknown    Class = iota // counts for nothing
    Knowledge               // pwd
    Possession              // otp, hwk, swk, application codes
    Federated               // an upstream identity provider; the application decides what it vouches for
)

// Factor describes one method. PhishingResistant is true only for methods
// whose proof is bound to the origin (WebAuthn).
type Factor struct {
    Class             Class
    PhishingResistant bool
}

// Policy classifies every method the application issues. A method absent
// from Factors counts for nothing: unknown is never a pass.
type Policy struct{ Factors map[Method]Factor }

// Standard classifies the RFC 8176 values above. Applications extend a copy
// with their own methods (a recovery code, an emailed code, a federated login).
func Standard() Policy

type Requirement uint8

const (
    AnyFactor         Requirement = iota + 1
    MultiFactor                   // a first factor plus a possession factor, or one WebAuthn assertion with mfa
    PhishingResistant             // MultiFactor with a phishing-resistant method among them
)

func (p Policy) Satisfies(methods []Method, r Requirement) bool
```

Rules:

- A first factor is a `Knowledge` or `Federated` method; multi-factor needs a
  first factor plus a `Possession` method, never two first factors: a password
  plus a federated login proves nothing about a device the user holds. Whether
  a federated login alone vouches for more is the application's call, made
  outside `Satisfies`.

- `mfa` counts only beside `hwk` or `swk` from the same assertion: `{swk, mfa}`
  is multi-factor (a user-verifying authenticator is a multi-factor
  cryptographic authenticator in NIST SP 800-63B-4 terms); `{mfa}` alone is
  nothing. Kratos counted a passkey as one factor and later reverted a change
  that counted it as two (#3853); the line here is explicit and tested: it is two
  only with user verification.
- `hwk` versus `swk` comes from the backup-eligibility flag, which the
  authenticator asserts. Neither says the key is hardware the verifier has
  checked. AAL3 needs verified attestation of a non-exportable key, so `amr`
  does not claim AAL3; the attestation policy that can (later) adds it.
- Freshness is a separate question from strength: `Fresh(authTime, within, now)`
  answers "recent enough for a settings change". Kratos once conflated the two
  and it was a reported vulnerability.
- `Satisfies` is exhaustively table-tested over every subset of the methods in
  the policy.

The method set holds only methods this application verified itself: a flat set
cannot say which assertion `mfa` came from, so never copy an upstream identity
provider's `amr` claim into it; record a federated sign-in as one
application-defined `Federated` method.

The application persists the method set as a JSON array on its session row or in
its token, beside the time of authentication.

### 5.4 `webauthn` — ceremonies (G1)

A thin, opinionated layer over `github.com/go-webauthn/webauthn`. go-webauthn
does the parsing and the cryptography; this package decides what is allowed,
binds every ceremony to its purpose, and owns the checks go-webauthn leaves to
its caller.

#### Configuration

```go
type Config struct {
    RPID       string        // registrable domain or the origin's host; fixed for the life of every credential
    RPName     string
    Origins    []string      // exact origins; https, except http://localhost for development
    Algorithms []int         // COSE; default -8, -7, -257 (WebAuthn Level 3 guidance)
    Timeout    time.Duration // default 5 min, at most 15 min
}

func New(cfg Config) (*RP, error)
```

`New` refuses a configuration where an origin's host is neither the RP ID nor a
subdomain of it. Cross-origin iframes are refused (`topOrigin` present). Origins
are compared exactly; the RP ID is never derived from a request header.
Attestation conveyance is `none`; an attestation policy is later work (§10).

#### Subjects and user handles

The library never sees a user record. A ceremony takes a `Subject`:

```go
type Subject struct {
    ID          string // the application's key; opaque to the library
    Name        string // shown by credential managers, e.g. an email address
    DisplayName string
}
```

The user handle (`user.id` in WebAuthn) is 64 bytes from `crypto/rand`, created
once per subject through `HandleStore.Ensure` and never changed. Reusing it means
a second registration on the same authenticator replaces that authenticator's
discoverable credential instead of piling up a duplicate. It is never the
subject ID.

#### Stores

```go
// CredentialStore holds WebAuthn credentials. Rename, delete and listing for a
// settings page are the application's own queries; the library calls only these.
type CredentialStore interface {
    // Insert stores a new credential. ErrDuplicate when ANY subject already
    // holds this credential ID (a unique index on the ID, not on (subject, ID)).
    Insert(ctx context.Context, c Credential) error

    // List returns the subject's credentials for this RP ID.
    List(ctx context.Context, subject, rpID string) ([]Credential, error)

    // RecordAssertion applies one verified assertion only while the stored
    // counter still equals u.PrevSignCount:
    //   UPDATE ... SET sign_count = ?, backup_eligible = ?, backup_state = ?,
    //     version = ?, last_used_at = ?
    //   WHERE subject = ? AND credential_id = ? AND sign_count = ?
    // applied=false means a concurrent assertion won; the caller fails.
    RecordAssertion(ctx context.Context, u AssertionUpdate) (applied bool, err error)

    // MarkCloneSuspected records a counter regression on the credential.
    MarkCloneSuspected(ctx context.Context, subject string, id []byte, at time.Time) error
}

// HandleStore maps subjects to their WebAuthn user handle.
type HandleStore interface {
    // Ensure returns the subject's handle, storing h first when it has none
    // (create-if-absent; two concurrent callers get the same handle back).
    Ensure(ctx context.Context, subject string, h []byte) ([]byte, error)
    // Subject resolves a handle from a discoverable assertion. ErrNotFound
    // when no subject holds it.
    Subject(ctx context.Context, handle []byte) (string, error)
}

type Credential struct {
    Version          uint16    // set by the library; zero on load is a store fault
    ID               []byte
    Subject          string
    RPID             string
    PublicKey        []byte    // COSE_Key
    Algorithm        int
    AAGUID           [16]byte  // kept for naming even when unattested
    Transports       []string  // self-reported; a hint, never evidence
    SignCount        uint32
    BackupEligible   bool      // fixed at creation
    BackupState      bool
    UVInitialized    bool
    Discoverable     *bool     // credProps rk; nil when the client did not report it
    CreatedAt        time.Time
    LastUsedAt       time.Time
    CloneSuspectedAt time.Time
}

// AssertionUpdate is what one verified assertion changes.
type AssertionUpdate struct {
    Subject       string
    CredentialID  []byte
    PrevSignCount uint32 // the counter the library read; the update applies only while it still holds
    SignCount     uint32
    BackupState   bool
    At            time.Time
}
```

`Version` is the credential's schema version, set by the library. Version 1 is
reserved for credentials imported from v1, whose backup flags were never recorded:
for those, the first assertion records the flags instead of comparing them and
moves the credential to the current version.

#### Ceremonies

| Function                                   | When                                                         | Options sent                                                                                                                                                                                                                                                                                     | UV                                                                                |
| ------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------- |
| `BeginRegistration` / `FinishRegistration` | an authenticated subject adds a credential                   | `excludeCredentials` = the subject's credentials; passkey: `residentKey: required`; security key: `residentKey: discouraged`, `hints: ["security-key"]`, `authenticatorAttachment: "cross-platform"`; optional `mediation: "conditional"` for an upgrade after a password sign-in (passkey only) | required for a passkey (preferred when conditional), preferred for a security key |
| `BeginPasskey` / `FinishPasskey`           | sign-in with no identifier                                   | no `allowCredentials`; usable with `mediation: "conditional"` (autofill) or modal                                                                                                                                                                                                                | required                                                                          |
| `BeginSecondFactor` / `FinishSecondFactor` | a subject the caller has already authenticated, or a step-up | `allowCredentials` = the subject's credentials                                                                                                                                                                                                                                                   | preferred; the caller may require it                                              |

Every `Begin` writes one `Flow` holding the ceremony kind, the caller's purpose
string (`"login"`, `"stepup"`, …), the subject (when known), the RP ID and the
go-webauthn session data, and returns the options as JSON the browser's
`PublicKeyCredential.parseCreationOptionsFromJSON` /
`parseRequestOptionsFromJSON` accepts. Every `Finish` takes the flow (single use),
checks kind, purpose and subject against what the caller expects, and accepts the
response as the browser's `toJSON()` output.

`Finish*` for an assertion returns verified facts and nothing else:

```go
type Verified struct {
    Subject      string
    CredentialID []byte
    UserVerified bool
    BackupEligible, BackupState bool
    AAGUID       [16]byte
    Methods      []amr.Method // hwk or swk, plus mfa when UserVerified
    At           time.Time
}
```

#### Checks the package owns

go-webauthn verifies the signature, the challenge, `type`, the origin against
the configured list, the RP ID hash and the flags it is asked to require. This
package adds, in order, and each is a test named for the attack:

1. The flow exists, is unexpired, unconsumed (atomic `Take`), of the expected kind
   and purpose, and, when the ceremony names a subject, for that subject.
2. `topOrigin` absent.
3. User presence set, except for a conditional create (WebAuthn Level 3 §7.1
   verifies UP only when mediation is not conditional). User verification set
   when the ceremony requires it; a passkey sign-in without it is refused, never
   downgraded.
4. Registration: algorithm in the allow-list; credential ID absent for every
   subject (`Insert` → `ErrDuplicate`, which the application must not resolve by
   re-binding); BE=0 with BS=1 refused.
5. Discoverable assertion: the user handle is present (a response without one
   is malformed, `ErrInvalidCredentials`) and resolves to a subject; the
   credential ID is among that subject's credentials for this RP ID. Either miss
   is `ErrUnknownCredential`.
6. Second-factor assertion: the credential is among the flow subject's
   credentials. A miss is `ErrInvalidCredentials`.
7. BE equals the stored value (it never changes; a change is refused and logged);
   BE=0 with BS=1 refused; a new BS is stored.
8. Counter: stored and received both 0 is normal (synced passkeys never count).
   Received greater than stored advances. Otherwise, with a non-zero stored
   counter, the credential is marked clone-suspected and the ceremony fails with
   `ErrCloneSuspected`, so the application can tell the owner. A canonical DER
   ECDSA signature is required (carried over from v1).
9. `RecordAssertion` must apply; `applied=false` fails the ceremony. A failed write
   is never a pass.

#### Deliberately not in G1

An attestation policy (`direct`/`enterprise`, an AAGUID allow-list, FIDO MDS3 the
operator downloads under its own terms); an AAGUID naming table (the application
supplies names; the community list carries no license, so the library cannot
ship it); a Related Origin Requests document helper; PRF and largeBlob.

### 5.5 `oidcrp` — relying party (G3)

`HandleCallback` returns **verified claims**. It does not look up a user, does not
create one, and does not know what a user is. F-01 becomes inexpressible.

```go
type Verified struct {
    Issuer        string
    Subject       string   // never empty; required by OIDC Core §2
    Email         string
    EmailVerified bool
    Claims        map[string]any // allow-listed
    AMR           []string       // upstream, if the provider was configured to be trusted
    ACR           string
}
```

Carried forward from v1, all now mandatory rather than opt-in: PKCE S256, nonce
with constant-time comparison, `azp` on multi-audience tokens, `sub` required,
`email_verified: false` refused, an outbound client from `httpx`.

New in v2:

- **`ProviderResolver`** replaces the boot-time static map. `Resolve(ctx, id)
(Provider, error)` — the application answers from a config file, a per-tenant
  database row, whatever it likes. This is what makes bring-your-own-connection
  expressible at all.
- **Sealed flow state.** The state parameter carries the flow ID, provider ID and
  PKCE verifier inside an XChaCha20-Poly1305 sealed blob with a key rotation list.
  Store-backed single use (`FlowStore.Take`) is the default.
- **Provider-asserted MFA, fail-closed.** `TrustedAAL2ACR []string` and
  `TrustedAAL2AMR []string` per provider, empty by default, so an upstream `acr`
  is never trusted as a second factor unless explicitly enumerated.
- **An outbound parameter allow-list.** See §10 for `login_hint`.

The library never links accounts. Where v1 had `LinkPolicy`, v2 returns a
`LinkProposal` the application acts on, and the default is that an assertion
matching an existing address proves nothing.

### 5.6 `attempt` — failed-attempt budgets (G2)

```go
type Counter interface {
    Incr(ctx context.Context, key string, window time.Duration) (n int, err error)
    Reset(ctx context.Context, key string) error
}
```

- **Increment before validating**, in its own transaction, so a rollback cannot
  undo the count.
- What the key is, per flow or per account, is open (§10).
- The **policy** — how many, how long — stays with the application. The library
  supplies the mechanism and the uniform-response discipline.

### 5.7 `normalize` — identifier normalisation (later)

PRECIS profiles for email and phone, ported from Kratos's `x/normalize.go`. This
closes the homoglyph and zero-width-joiner duplicate-account attack. Two modes:
strict at registration, graceful at lookup — and the graceful path must **re-run
the whole pipeline** after stripping forbidden runes.

### 5.8 `audit` (later)

The event vocabulary and a `Logger` interface. Events are emitted **from the
primitives**: 652 lines of hand-mirrored decorators meant that any method added
upstream was silently un-audited (F-22, F-34). No wrappers in v2.

---

## 6. Errors and the enumeration discipline

One sentinel, `ErrInvalidCredentials`, returned for an unknown identifier, a
subject with no credential of that kind, and a wrong proof alike. All three cost
the same work.

**v2 does not export a distinguishable not-found on any path that takes an
identifier.** If it did, someone would `errors.Is` on it and rebuild the oracle in
their handler. `store.ErrNotFound` exists for the store contract; the
authentication functions never surface it.

**F-29 is closed by construction.** v2 has no identifier-first passkey sign-in:
`BeginPasskey` takes no identifier and answers everyone identically, and
`BeginSecondFactor` runs only for a subject the caller has already
authenticated. Nothing a stranger can submit reveals whether an account exists or
which credentials it holds.

Two narrow, documented exceptions, both after a valid signature or on a path that
takes no identifier:

- `ErrUnknownCredential` (discoverable sign-in only): the presented credential
  maps to no subject. The holder of that credential learns only that this RP has
  forgotten it, which is what WebAuthn Level 3's
  `PublicKeyCredential.signalUnknownCredential` exists to act on.
- `ErrCloneSuspected`: the signature was valid and the counter went backwards.

Timing is equalised by doing the real work — the v1 dummy-hash approach — not by
sleeping.

---

## 7. `batteries` — deferred

Batteries would compose primitives into working flows so that a consumer is not
obliged to reassemble one correctly. That convenience is exactly what produced
F-01, F-11, F-12, F-15, F-29, F-30 and F-35, so v2.0 ships building blocks and a
runnable example (`examples/passkeys`: a `net/http` server, an in-memory store
that is explicitly not for production, and the browser calls) instead. Batteries
come when a second application needs the same flow, and must then clear these
bars:

**Risk 1 — fail-open on wiring the library cannot verify.** F-35 exactly.
_Mitigation:_ every battery dependency is a constructor argument, validated at
construction, with no nil-tolerant field and no zero-value-usable type. A battery
that cannot answer a question refuses; it never degrades.

**Risk 2 — the default decides security.** _Mitigation:_ no enum whose wrong value
is a bypass. Where two behaviours genuinely differ, they are two constructors with
names you have to type.

**Risk 3 — batteries accrete identity decisions.** F-01 began as a convenience.
_Mitigation:_ `batteries/` may not import a user store, and the linter enforces
it. It takes application callbacks and returns decisions.

**Risk 4 — a battery blinds its own observability.** F-22, F-34.
_Mitigation:_ no decorators. Primitives emit; batteries pass a logger through.

---

## 8. Migration from v1

v2 is a new import path, so nothing breaks by upgrading — a consumer moves when
it chooses. The migration document must cover, at minimum:

- `UserStore` is gone. The application already had a user table; it now uses it
  directly and calls the library for verification only.
- WebAuthn credentials registered by v1 carry over as second factors: a v1
  credential's user handle is the subject ID, so the application seeds its
  `HandleStore` with that value for those subjects (`Ensure` then returns it, and
  their discoverable sign-in resolves). Their backup flags move from v1's metadata
  keys into the typed fields; a credential whose flags were never recorded is
  imported with `Version: 1` and takes them from its next assertion (§5.4).
- Password digests carry forward unchanged: the v2 verifier understands bcrypt
  and reports `NeedsRehash` so a deployment migrates to argon2id on next sign-in.
- TOTP `$gat1$` secrets and `$gab1$`/`$gab2$` recovery digests stay verifiable
  in G2, with golden vectors.
- Reset and verification token digests carry forward, but the HMAC keying is new,
  so live tokens are invalidated. TTLs are one and twenty-four hours; the window
  closes on its own.
- `middleware.BasicAuthMiddleware`, the vendor provider constructors and the
  audit wrappers have no replacement. The migration guide names what to write
  instead.

v1.x receives security fixes for twelve months from the v2.0.0 release, with the
end date stated in `SECURITY.md`.

---

## 9. Testing

Everything v1 established: every fix ships with a test that fails when the fix is
reverted; tests are named for the attack and cite the RFC or CVE class; a mutation
gate proves the suite bites; adversarial suites per package; fuzz targets on every
parser reachable with attacker-controlled bytes.

**Conformance suites the application runs against its own store.** `authtest` is
a normal importable package, not a `_test.go` file:

```go
func TestMyStores(t *testing.T) {
    authtest.FlowStoreSuite(func(t *testing.T) store.FlowStore { … })(t)
    authtest.WebAuthnStoreSuite(authtest.WebAuthnHarness{
        NewStores:  func(t *testing.T) (webauthn.CredentialStore, webauthn.HandleStore) { … },
        NewSubject: func(t *testing.T) string { … }, // a subject your store accepts
    })(t)
}
```

They cover what an application will otherwise get wrong: `Take` and `Ensure` race
N goroutines and exactly one wins (or all agree); a credential ID held by one
subject cannot be inserted for another; `RecordAssertion` loses cleanly to a
concurrent update; expiry is enforced on read, not by a sweeper; every exported
field round-trips (§4.2 rule 4); not-found is never confused with success.

**A virtual authenticator.** `authtest` ships a software authenticator (ES256 and
Ed25519 keys, attestation `none`, settable flags and counters, and the means to
forge a wrong origin, RP ID hash, challenge or type) so that every check in §5.4
has a test that produces the attack, not a mock that pretends to.

Vulnerability reproductions become tests in the package, named for the attack —
never standalone programs in the tree, which rot and ship in the module zip.

---

## 10. Open questions

1. **Attempt budgets: per flow or per account.** Keying only on the flow means a
   fresh flow is a fresh budget; keying on the account lets an attacker spend a
   victim's budget. A production consumer runs per-account budgets split by
   surface (password sign-in, federated hand-off, step-up), so spending one
   cannot lock another. Decide in G2's design.
2. **`login_hint`.** The earlier draft excluded it from the outbound allow-list
   (a caller-supplied value steers account selection at several IdPs). Binding
   the address a person typed to the sign-in needs it, together with a check that
   the asserted address matches. Decide in G3's design.
3. **Attestation policy.** `direct`/`enterprise` attestation, an AAGUID
   allow-list and FIDO MDS3: MDS3 has usage terms a relying party accepts, so the
   library takes a provider the operator configures and never bundles the blob.
4. **Whether `hash` ships a HIBP breach check.** A network call from a library.
   Proposed: the k-anonymity client behind an explicit constructor, absent by
   default, fail-open-on-network-error left to the caller.

---

## 11. Phases, versions and dependencies

| Phase | Packages                                                                                                                                                            | Ships as         |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- |
| G1    | `amr`, `webauthn`, `store` (FlowStore), `authtest` (flow + WebAuthn suites, virtual authenticator), `examples/passkeys`                                             | `v2.0.0-alpha.N` |
| G2    | `challenge` (hand-off token, durable state, step-up), `attempt`, `totp` (durable replay guard), `recovery` (keyed digests with a key fingerprint, legacy verifiers) | `v2.0.0-beta.N`  |
| G3    | `session` (refresh families, reuse detection, hashed tokens), `token`, `oidcrp`, `httpx`, `jwtx`                                                                    | `v2.0.0`         |
| later | `hash`, `normalize`, `audit`, `httpmw`, an attestation policy, a reference SQL store, `batteries`                                                                   | `v2.x`           |

- G1 exit: every check in §5.4 has a virtual-authenticator test that fails when
  the check is removed; the conformance suites pass against the example's store
  and against a production consumer's SQL store; coverage floors set from measured
  values.
- Alpha and beta tags may change APIs; `v2.0.0` freezes them under §4.2 rule 5.
- `github.com/go-webauthn/webauthn` is pinned to an exact version (v0.18.2 at
  G1). It is effectively single-maintainer, so every bump reads its changelog and
  runs the full suite, and the checks in §5.4 stay in this package even where
  go-webauthn also performs them.
- Go 1.26 is the floor because go-webauthn v0.18 requires it.
- v1 stays on a `v1` maintenance branch for twelve months of security fixes.

---

## 12. Decision log

- **2026-10-17 — storage.** Typed stores for durable credentials, one opaque
  single-use store for ceremony state, stores passed per call, named atomic
  operations, reflective field round-trip, interfaces never gain methods (§4).
- **2026-10-17 — passkeys count as two factors only with user verification**
  (§5.3), and passkey sign-in is discoverable only, which closes F-29 (§6).
- **2026-10-17 — no HTTP handlers in the core.** Building blocks and a runnable
  example; batteries deferred (§7).
- **2026-10-17 — dependency.** go-webauthn, pinned exactly; Go 1.26 floor (§11).
