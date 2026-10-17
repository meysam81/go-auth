# go-auth v2 G1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `main` into the `github.com/meysam81/go-auth/v2` module and ship
G1 (`amr`, `store`, `webauthn`, `authtest`, `examples/passkeys`) as
`v2.0.0-alpha.1`.

**Architecture:** v1 moves to a `v1` branch; `main` becomes the v2 module at the
repository root. `webauthn` wraps `github.com/go-webauthn/webauthn` v0.18.2 and
owns every policy check the design lists; it never stores anything itself but
calls the typed store interfaces the caller passes per call. `authtest` ships a
virtual authenticator, in-memory stores (tests and the example only) and the
conformance suites applications run against their own stores.

**Tech Stack:** Go 1.26, `github.com/go-webauthn/webauthn` v0.18.2 (and its
`protocol`, `protocol/webauthncbor`, `protocol/webauthncose` packages),
stdlib `encoding/json`, `crypto/ecdsa`, `crypto/ed25519`.

**Spec:** `docs/v2-design.md` (§2, §4, §5.3, §5.4, §6, §9, §11, §12).

## Global Constraints

- Module path `github.com/meysam81/go-auth/v2`; `go 1.26.0` in `go.mod`.
- `github.com/go-webauthn/webauthn` pinned exactly at `v0.18.2`.
- Direct imports only from the `.golangci.yml` depguard allow-list (stdlib,
  `github.com/meysam81/go-auth`, `golang.org/x/crypto`, `golang.org/x/oauth2`,
  `github.com/golang-jwt/jwt/v5`, `github.com/coreos/go-oidc/v3`,
  `github.com/go-webauthn/webauthn`, `github.com/pquerna/otp`). G1 adds none.
- No user store, no identity decisions: a subject is an opaque `string`.
- JSON through stdlib `encoding/json` (go-webauthn's options use `omitzero`).
- Defaults: algorithms `[-8, -7, -257]`; timeout 5 min, allowed 30 s to 15 min;
  user handle 64 bytes from `crypto/rand`; flow ID 32 bytes from `crypto/rand`,
  base64url; responses larger than 64 KiB are refused.
- Every verification failure satisfies `errors.Is(err, ErrInvalidCredentials)`
  except the two documented exceptions (`ErrUnknownCredential`,
  `ErrCloneSuspected`) and `store.ErrDuplicate` at registration; the error
  string carries a reason for logs, never the go-webauthn `DevInfo` verbatim to
  a client.
- errcheck runs with `check-blank: true`: no `_ =` discards.
- Each §5.4 check has a test named for the attack that fails when the check is
  removed.
- Commits: conventional commits; no `Co-Authored-By`; a `Claude-Session`
  trailer. No reference to any consuming product in code, docs, commits or PR
  text.

## Review Focus

- A response body that is not JSON, is truncated, or is huge must fail with
  `ErrInvalidCredentials` before any store call (Task 6 and Task 7 tests).
- The same assertion submitted twice concurrently must yield exactly one success
  (Task 7 `TestPasskey_ConcurrentReplay_OneWinner`).
- A configured origin with a trailing slash, a path or an uppercase host must be
  refused by `New`, not silently normalised (Task 4).
- A credential removed between `Begin` and `Finish` must fail the second-factor
  ceremony (Task 8 `TestSecondFactor_CredentialRemovedMidCeremony`).
- A store that returns a credential with an empty public key or zero `Version`
  must fail closed, never verify (Task 7
  `TestPasskey_StoreFault_EmptyPublicKey`).

---

### Task 1: Cut v1 and turn `main` into the v2 module with `store`

**Files:**

- Delete: `audit/`, `auth/`, `middleware/`, `provider/`, `session/`,
  `storage/`, `examples/basic/`, `examples/jwt/`, `examples/oidc/`,
  `examples/complete/`, `ROADMAP.md`
- Modify: `go.mod`, `go.sum`, `.coverage-floor`, `release-please-config.json`,
  `README.md`, `SECURITY.md`, `CLAUDE.md`
- Create: `store/store.go`, `store/doc.go`

**Interfaces:**

- Produces: `store.Flow{Kind string; Payload []byte; ExpiresAt time.Time}`,
  `store.FlowStore` (`Put(ctx, id string, f Flow) error`,
  `Take(ctx, id string) (Flow, error)`), `store.ErrNotFound`,
  `store.ErrDuplicate`.

- [ ] **Step 1: Branch the work and cut `v1` locally**

Work in `/home/meysam/codes/personal/go-auth-v2-design` (holds the design and
this plan). Run `git branch -m docs/v2-design feat/v2-g1` and
`git branch v1 origin/main`. Pushing `v1` is outward-facing: ask the founder
before `git push origin v1`.

- [ ] **Step 2: Move the module to v2**

Set `module github.com/meysam81/go-auth/v2` and `go 1.26.0`; delete the v1
packages and `ROADMAP.md` listed above; `go get
github.com/go-webauthn/webauthn@v0.18.2`; `go mod tidy`.

- [ ] **Step 3: Write `store`**

`store/store.go` holds the `Flow`/`FlowStore` contract verbatim from design
§4.1 (including the `Take` doc comment) and the two sentinels
(`ErrNotFound = errors.New("store: not found")`,
`ErrDuplicate = errors.New("store: duplicate")`). `doc.go` states the typed
versus opaque split in two sentences.

- [ ] **Step 4: Release config for prereleases**

In `release-please-config.json` set, under `"."`, `"prerelease": true`,
`"prerelease-type": "alpha"`, `"versioning": "prerelease"` and
`"release-as": "2.0.0-alpha.1"`. Confirm these keys against
`https://github.com/googleapis/release-please/blob/main/docs/customizing.md`
before committing; remove `release-as` after the first alpha ships.

- [ ] **Step 5: Docs**

`README.md`: replace the feature tour with a v2 alpha header (what G1
contains, that v1 lives on the `v1` branch and its import path is unchanged).
`SECURITY.md`: supported versions table — `2.0.0-alpha.*` best effort, `1.x`
security fixes for twelve months from `v2.0.0`. `CLAUDE.md`: replace the v1
project structure with the §2 package table.

- [ ] **Step 6: Verify**

Run: `go build ./... && go vet ./...` → exit 0.
Run: `golangci-lint run` → `0 issues`.
Empty `.coverage-floor` package lines; floors are set in Task 10.

- [ ] **Step 7: Commit**

```bash
git add -A -- go.mod go.sum store .coverage-floor release-please-config.json README.md SECURITY.md CLAUDE.md
git add -u
git commit  # feat!: move main to the v2 module; v1 continues on the v1 branch
```

Body includes a `BREAKING CHANGE:` footer naming the new import path.

---

### Task 2: `amr` — methods, factor classes, policy

**Files:**

- Create: `amr/amr.go`, `amr/doc.go`
- Test: `amr/amr_test.go`

**Interfaces:**

- Produces: `type Method string` with `PWD="pwd"`, `OTP="otp"`, `HWK="hwk"`,
  `SWK="swk"`, `MFA="mfa"`; `type Class uint8` (`Unknown`, `Knowledge`,
  `Possession`, `Federated`); `type Factor struct{ Class Class;
PhishingResistant bool }`; `type Policy struct{ Factors map[Method]Factor }`;
  `func Standard() Policy`; `func (p Policy) With(m Method, f Factor) Policy`
  (returns a copy); `type Requirement uint8` (`AnyFactor=1`, `MultiFactor`,
  `PhishingResistant`); `func (p Policy) Satisfies(methods []Method, r
Requirement) bool`; `func Fresh(authTime time.Time, within time.Duration, now
time.Time) bool`.

- [ ] **Step 1: Write the failing tests**

```go
// app methods used by the tests
var app = amr.Standard().
    With("sso", amr.Factor{Class: amr.Federated}).
    With("rc", amr.Factor{Class: amr.Possession}).
    With("email", amr.Factor{Class: amr.Possession})

func TestSatisfies(t *testing.T) {
    tests := []struct {
        name          string
        set           []amr.Method
        any, mf, phr  bool
    }{
        {"password only", []amr.Method{"pwd"}, true, false, false},
        {"password and totp", []amr.Method{"pwd", "otp"}, true, true, false},
        {"user-verified synced passkey", []amr.Method{"swk", "mfa"}, true, true, true},
        {"device-bound key without UV", []amr.Method{"hwk"}, true, false, false},
        {"password and security key", []amr.Method{"pwd", "hwk"}, true, true, true},
        {"mfa alone", []amr.Method{"mfa"}, false, false, false},
        {"mfa beside otp is not webauthn", []amr.Method{"otp", "mfa"}, true, false, false},
        {"empty", nil, false, false, false},
        {"unknown value", []amr.Method{"xyz"}, false, false, false},
        {"sso alone", []amr.Method{"sso"}, true, false, false},
        {"sso and totp", []amr.Method{"sso", "otp"}, true, true, false},
        {"password and sso are two first factors", []amr.Method{"pwd", "sso"}, true, false, false},
        {"recovery path", []amr.Method{"pwd", "rc", "email", "otp"}, true, true, false},
        {"sso and passkey", []amr.Method{"sso", "swk"}, true, true, true},
    }
    // assert app.Satisfies(tt.set, AnyFactor/MultiFactor/PhishingResistant) == tt.any/mf/phr
}

func TestSatisfies_ExhaustiveImplications(t *testing.T) // every subset of
// {pwd,otp,hwk,swk,mfa,sso,rc}: PhishingResistant ⇒ MultiFactor ⇒ AnyFactor,
// and the result is unchanged by order and by duplicated entries.

func TestStandard_ReturnsIndependentCopies(t *testing.T) // mutating one
// Standard().Factors map does not change the next Standard() call; With does
// not mutate its receiver.

func TestFresh(t *testing.T) // zero authTime false; authTime after now false;
// now-authTime == within true; within+1ns false.
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./amr/` → FAIL (package does not exist).

- [ ] **Step 3: Implement `amr/amr.go`**

`Standard()` classifies `pwd` Knowledge, `otp` Possession, `hwk`/`swk`
Possession with `PhishingResistant: true`; `mfa` is not in `Factors` (it is a
modifier). `Satisfies`: a method absent from `Factors` and not `mfa` counts for
nothing. AnyFactor = any classified method. MultiFactor = (a Knowledge or
Federated method AND a Possession method) OR (`mfa` AND (`hwk` OR `swk`)).
PhishingResistant = MultiFactor AND a method with `PhishingResistant`.

- [ ] **Step 4: Run to verify pass**

Run: `go test -race ./amr/` → PASS.

- [ ] **Step 5: Commit** — `feat(amr): RFC 8176 methods, factor classes and a fail-closed policy`

---

### Task 3: `authtest` virtual authenticator

**Files:**

- Create: `authtest/doc.go`, `authtest/authenticator.go`
- Test: `authtest/authenticator_test.go`

**Interfaces:**

- Produces:

  ```go
  type AuthenticatorConfig struct {
      Algorithm       int      // -7 (ES256, default) or -8 (Ed25519)
      AAGUID          [16]byte
      BackupEligible  bool
      BackupState     bool
      UserVerified    bool
      SignCount       uint32   // initial counter
      CounterStep     uint32   // added per assertion; 0 models a synced passkey
      Discoverable    bool     // reported as credProps.rk when requested
  }
  type Ceremony struct {      // what the authenticator is about to sign; a Tamper edits it
      Type, Challenge, Origin, TopOrigin string
      CrossOrigin      bool
      RPID             string
      Flags            byte   // UP 0x01, UV 0x04, BE 0x08, BS 0x10 (AT added for create)
      SignCount        uint32
      CredentialID     []byte
      UserHandle       []byte
      OmitCredProps    bool
      CorruptSignature bool
      RawECDSA         bool   // sign ES256 as raw r||s instead of ASN.1 DER
  }
  type Tamper func(*Ceremony)
  func NewAuthenticator(cfg AuthenticatorConfig) (*Authenticator, error)
  func (a *Authenticator) Register(optionsJSON []byte, origin string, t ...Tamper) ([]byte, error)
  func (a *Authenticator) Assert(optionsJSON []byte, origin string, t ...Tamper) ([]byte, error)
  func (a *Authenticator) CredentialID() []byte
  func (a *Authenticator) SetSignCount(n uint32)
  ```

  `optionsJSON` is the `publicKey` object (`Begun.Options`); the return value is
  the browser's `PublicKeyCredential.toJSON()` shape. `Register` remembers the
  user handle from `user.id`; `Assert` includes it as `userHandle` only when
  `Discoverable`. `credProps` is reported only when the options request it.

- [ ] **Step 1: Write the failing tests** (against bare go-webauthn, to prove
      the authenticator itself)

`TestAuthenticator_ES256_RegistersAndAsserts` and
`TestAuthenticator_Ed25519_RegistersAndAsserts`: `webauthn.New` with RPID
`example.test` and origin `https://app.example.test`; `BeginRegistration` →
`Register` → `ParseCredentialCreationResponseBytes` → `CreateCredential` OK;
`BeginLogin` → `Assert` → `ParseCredentialRequestResponseBytes` →
`ValidateLogin` OK with `SignCount` advanced by `CounterStep`.
`TestAuthenticator_TamperOrigin_FailsVerification` (errors.As
`*protocol.Error` with `Type == "verification_error"`) and
`TestAuthenticator_CorruptSignature_FailsSignature` (`Type ==
"invalid_signature"`).

- [ ] **Step 2: Run to verify failure** — `go test ./authtest/` → FAIL.

- [ ] **Step 3: Implement `authtest/authenticator.go`**

authData = sha256(rpId) | flags | signCount (big-endian uint32) | for create:
AAGUID | uint16 credId length | credId | COSE key. COSE key via
`webauthncose.EC2PublicKeyData{PublicKeyData{KeyType: 2, Algorithm: -7}, Curve:
1, XCoord, YCoord}` (32-byte padded) or `OKPPublicKeyData` (`KeyType: 1,
Algorithm: -8, Curve: 6`); attestationObject `{fmt:"none", attStmt:{},
authData}` via `webauthncbor.Marshal`. clientDataJSON `{"type","challenge",
"origin"}` plus `crossOrigin`/`topOrigin` only when set. ES256 signs
`ecdsa.SignASN1` over sha256(authData || sha256(clientDataJSON)); Ed25519 signs
the raw concatenation. Credential ID: 32 random bytes per authenticator. Binary
JSON fields are unpadded base64url.

- [ ] **Step 4: Run to verify pass** — `go test -race ./authtest/` → PASS.

- [ ] **Step 5: Commit** — `feat(authtest): virtual WebAuthn authenticator with tamper hooks`

---

### Task 4: `webauthn` configuration, types and errors

**Files:**

- Create: `webauthn/doc.go`, `webauthn/config.go`, `webauthn/types.go`,
  `webauthn/errors.go`
- Test: `webauthn/config_test.go`

**Interfaces:**

- Produces:

  ```go
  type Config struct {
      RPID       string
      RPName     string
      Origins    []string
      Algorithms []int         // default -8, -7, -257
      Timeout    time.Duration // default 5 min
      Now        func() time.Time // nil = time.Now
  }
  type RP struct{ /* unexported */ }
  func New(cfg Config) (*RP, error)
  func (rp *RP) ID() string

  type Subject struct{ ID, Name, DisplayName string }
  type CredentialKind uint8 // Passkey = 1, SecurityKey = 2
  const CurrentVersion uint16 = 2 // 1 = imported from v1, backup flags unknown
  type Credential struct { /* exactly the fields in design §5.4 */ }
  type AssertionUpdate struct {
      Subject        string
      CredentialID   []byte
      PrevSignCount  uint32
      SignCount      uint32
      BackupEligible bool   // equals the stored value except when adopting a Version 1 credential
      BackupState    bool
      Version        uint16 // CurrentVersion after any assertion
      At             time.Time
  }
  type CredentialStore interface { Insert; List(ctx, subject, rpID string) ([]Credential, error); RecordAssertion; MarkCloneSuspected } // per design §5.4
  type HandleStore interface { Ensure(ctx, subject string, h []byte) ([]byte, error); Subject(ctx, handle []byte) (string, error) }
  type Begun struct {
      FlowID    string
      Options   json.RawMessage // the publicKey object for parse*OptionsFromJSON
      Mediation string          // "" or "conditional"
  }
  type Expect struct{ FlowID, Purpose, Subject string }
  type Verified struct { /* design §5.4 */ }
  var ErrInvalidCredentials, ErrUnknownCredential, ErrCloneSuspected error
  ```

  `AssertionUpdate` gains `BackupEligible` and `Version` beyond the design
  sketch so a Version 1 credential (design §8) adopts its flags in the same
  conditional update; the store's SQL sets them alongside `backup_state`.

- [ ] **Step 1: Write the failing tests**

`TestNew_RejectsBadConfig` table, each expecting an error: empty RPID; RPID
with scheme, port or path; RPID that is an IP; no origins;
`https://app.example.test/` (trailing slash); `https://app.example.test/x`;
`https://App.Example.Test` (uppercase host); `http://app.example.test`
(http outside localhost); origin host `evil.test` for RPID `example.test`;
`Algorithms` containing `-35`; `Timeout` 10 s; `Timeout` 16 min.
`TestNew_AcceptsLocalhostHTTP` (RPID `localhost`, origin
`http://localhost:8080`). `TestNew_Defaults` (algorithms `[-8,-7,-257]`,
timeout 5 min). `TestRP_ID` returns the RPID.

- [ ] **Step 2: Run to verify failure** — `go test ./webauthn/` → FAIL.

- [ ] **Step 3: Implement**

`New` validates as tested, then builds `gowebauthn.Config{RPID, RPDisplayName:
RPName, RPOrigins: Origins, RPTopOriginVerificationMode:
protocol.TopOriginExplicitVerificationMode, AttestationPreference:
protocol.PreferNoAttestation, Timeouts: Login and Registration {Enforce: true,
Timeout: t, TimeoutUVD: t}}` (no `RPTopOrigins`, `RPAllowCrossOrigin` false,
unsolicited extension outputs rejected) and keeps the `*gowebauthn.WebAuthn`.
Errors (`errors.go`): the three sentinels plus an unexported `failure{sentinel,
reason string, cause error}` whose `Is` matches its sentinel and whose `Error()`
is `"webauthn: <reason>: <cause>"`; every later task returns failures through
it.

- [ ] **Step 4: Run to verify pass** — `go test -race ./webauthn/` → PASS.

- [ ] **Step 5: Commit** — `feat(webauthn): relying-party config, stored types and error sentinels`

---

### Task 5: In-memory stores and conformance suites

**Files:**

- Create: `authtest/memory.go`, `authtest/roundtrip.go`,
  `authtest/flowsuite.go`, `authtest/webauthnsuite.go`
- Test: `authtest/memory_test.go`

**Interfaces:**

- Consumes: `store.FlowStore`, `webauthn.CredentialStore`,
  `webauthn.HandleStore`, `webauthn.Credential` (Tasks 1, 4).
- Produces:

  ```go
  func NewMemoryFlowStore(now func() time.Time) store.FlowStore // nil = time.Now
  type MemoryWebAuthnStore struct{ /* mutex-guarded maps */ }
  func NewMemoryWebAuthnStore() *MemoryWebAuthnStore // satisfies CredentialStore and HandleStore
  func (m *MemoryWebAuthnStore) Delete(subject string, id []byte) // test helper
  func FlowStoreSuite(newStore func(t *testing.T) store.FlowStore) func(t *testing.T)
  type WebAuthnHarness struct {
      NewStores  func(t *testing.T) (webauthn.CredentialStore, webauthn.HandleStore)
      NewSubject func(t *testing.T) string // a subject the application's store accepts (e.g. a real user row)
  }
  func WebAuthnStoreSuite(h WebAuthnHarness) func(t *testing.T)
  func FillNonZero(t *testing.T, v any) // reflection filler used by the suites
  ```

  The suites draw every subject from `NewSubject` (an application's store may
  hold a foreign key to its users) and overwrite `Subject` after
  `FillNonZero`. The memory types' doc comments say: for tests and examples,
  never production.

- [ ] **Step 1: Write the failing test** — `TestMemoryStores_PassSuites` runs both
      suites against the memory stores (`NewSubject` returns a fresh random
      string).

- [ ] **Step 2: Run to verify failure** — FAIL (undefined).

- [ ] **Step 3: Implement the suites** as named subtests:

`FlowStoreSuite`: `PutThenTake`; `SecondTakeIsNotFound`;
`ExpiredIsNotFound` (ExpiresAt one hour in the past); `UnknownIsNotFound`;
`ConcurrentTake_OneWinner` (32 goroutines, exactly one success, the rest
`store.ErrNotFound`); `RoundTripsEveryField` (`FillNonZero` on a `Flow`,
payload containing `0x00` and `0xff`).
`WebAuthnStoreSuite`: `InsertThenList`;
`DuplicateIDSameSubject_ErrDuplicate`; `DuplicateIDOtherSubject_ErrDuplicate`;
`ListFiltersByRPID`; `ListOtherSubjectIsEmpty`;
`RecordAssertion_Applies`; `RecordAssertion_StaleCounter_NotApplied`;
`ConcurrentRecordAssertion_OneWinner`; `MarkCloneSuspected_Visible`;
`Ensure_CreatesOnce` (a second `Ensure` with different bytes returns the first);
`ConcurrentEnsure_AllAgree`; `SubjectByHandle`;
`UnknownHandle_ErrNotFound`; `CredentialRoundTripsEveryField`.
`FillNonZero` sets every exported field to a distinct non-zero value (strings,
byte slices, bools, unsigned and signed ints, `[16]byte`, `[]string`, `*bool`,
`time.Time` as a whole-second UTC instant) and calls `t.Fatalf` on any other
kind, so a new field of a new kind forces the suite to learn it.

- [ ] **Step 4: Implement the memory stores**, then run
      `go test -race ./authtest/` → PASS.

- [ ] **Step 5: Commit** — `feat(authtest): conformance suites and in-memory stores`

---

### Task 6: Registration ceremony

**Files:**

- Create: `webauthn/flow.go`, `webauthn/user.go`, `webauthn/register.go`
- Test: `webauthn/register_test.go`

**Interfaces:**

- Consumes: Tasks 3-5.
- Produces:

  ```go
  type RegistrationOptions struct {
      Kind        CredentialKind
      Purpose     string
      Conditional bool // mediation "conditional" (an upgrade after a password sign-in)
  }
  func (rp *RP) BeginRegistration(ctx context.Context, flows store.FlowStore, creds CredentialStore, handles HandleStore, sub Subject, opts RegistrationOptions) (Begun, error)
  func (rp *RP) FinishRegistration(ctx context.Context, flows store.FlowStore, creds CredentialStore, e Expect, response []byte) (Credential, error)
  ```

  `flow.go` (shared by Tasks 7-8): flow kinds `"webauthn.register"`,
  `"webauthn.passkey"`, `"webauthn.second_factor"`; payload `{purpose, subject,
handle, rp_id, require_uv, session}` where `session` is go-webauthn's
  `SessionData` as JSON (decoded into a fresh value); `newFlowID()`;
  `takeFlow(ctx, flows, e, kind)` returns the payload or a failure.
  `user.go`: an adapter implementing go-webauthn's `User` from (handle,
  subject name, display name, []Credential); it rebuilds `CredentialFlags`
  with `NewCredentialFlags` from the stored bools.

- [ ] **Step 1: Write the failing tests** (virtual authenticator + memory
      stores; RP `example.test`, origin `https://app.example.test`)

- `TestRegister_Passkey_StoresCredential`: `List` returns one credential with
  `Version == CurrentVersion`, `RPID`, `Subject`, non-empty `PublicKey`,
  `Algorithm == -7`, `*Discoverable == true`, `UVInitialized == true`,
  `CreatedAt == now`.
- `TestRegister_Passkey_Options`: unmarshalled `Begun.Options` has
  `authenticatorSelection.residentKey == "required"`, `userVerification ==
"required"`, `attestation == "none"`, `pubKeyCredParams` algs exactly
  `[-8,-7,-257]`, `extensions.credProps == true`, `user.id` decodes to 64 bytes,
  `excludeCredentials` empty; `Begun.Mediation == ""`.
- `TestRegister_SecurityKey_Options`: `residentKey == "discouraged"`,
  `userVerification == "preferred"`, `hints == ["security-key"]`.
- `TestRegister_ExcludesExistingCredentials`: second Begin lists the first
  credential's ID in `excludeCredentials`.
- `TestRegister_UserHandleStableAcrossRegistrations`.
- `TestRegister_Conditional`: `Begun.Mediation == "conditional"`,
  `userVerification == "preferred"`, and a response with UP=0 and UV=0
  completes.
- Refusals, each `errors.Is(err, ErrInvalidCredentials)` and nothing stored:
  `_WrongOrigin`, `_TopOrigin` (crossOrigin true + topOrigin),
  `_ReplayedFlow` (second Finish on the same flow), `_ExpiredFlow` (memory flow
  clock advanced 6 min), `_WrongPurpose`, `_WrongSubject`,
  `_FlowOfAnotherKind` (a passkey sign-in flow ID), `_DisallowedAlgorithm`
  (RP `Algorithms: []int{-7}`, Ed25519 authenticator),
  `_BackupStateWithoutEligibility` (BS=1, BE=0), `_NotJSON`,
  `_OversizedResponse` (64 KiB + 1).
- `TestRegister_SameAuthenticatorOtherSubject_ErrDuplicate`
  (`errors.Is(err, store.ErrDuplicate)`; subject B holds nothing).

- [ ] **Step 2: Run to verify failure** — FAIL.

- [ ] **Step 3: Implement**

Begin: validate `sub.ID`, `sub.Name`, `opts.Kind`, `opts.Purpose` non-empty;
`handles.Ensure(ctx, sub.ID, random64)`; `creds.List(ctx, sub.ID, rp.ID())`
with every loaded credential checked against design §4.2 rule 3; options
`WithExclusions`, `WithCredentialParameters` (configured algorithms),
`WithExtensions(WithExtensionCredProps())`, `WithConveyancePreference(none)`;
Passkey: `WithResidentKeyRequirement(Required)` and UV required (preferred when
`Conditional`); SecurityKey: residentKey discouraged, UV preferred,
`WithPublicKeyCredentialHints(security-key)`; `BeginMediatedRegistration(...,
MediationConditional)` when `Conditional`. Put the flow with `ExpiresAt =
session.Expires`. Options JSON is `json.Marshal(creation.Response)`.
Finish: size check → `takeFlow` → `ParseCredentialCreationResponseBytes` →
`CreateCredential` → map to `Credential{Version: CurrentVersion, ...,
Discoverable: cred.Extensions.RK, CreatedAt: now}` → `creds.Insert`.

- [ ] **Step 4: Run to verify pass** — `go test -race ./webauthn/` → PASS.

- [ ] **Step 5: Commit** — `feat(webauthn): registration with exclusions, purpose binding and unique credential IDs`

---

### Task 7: Passkey sign-in (discoverable) and the shared assertion checks

**Files:**

- Create: `webauthn/assert.go`, `webauthn/passkey.go`
- Test: `webauthn/passkey_test.go`

**Interfaces:**

- Produces:

  ```go
  type PasskeyOptions struct {
      Purpose     string
      Conditional bool // mediation "conditional" (autofill)
  }
  func (rp *RP) BeginPasskey(ctx context.Context, flows store.FlowStore, opts PasskeyOptions) (Begun, error)
  func (rp *RP) FinishPasskey(ctx context.Context, flows store.FlowStore, creds CredentialStore, handles HandleStore, e Expect, response []byte) (Verified, error)
  ```

  `assert.go` (used by Task 8): `func (rp *RP) settle(ctx, creds, stored
Credential, got *gowebauthn.Credential, now time.Time) (Verified, error)` —
  clone check, `RecordAssertion`, `Verified` construction.

- [ ] **Step 1: Write the failing tests**

- `TestPasskey_SyncedPasskey` (BE=1, BS=1, UV, counter step 0): `Verified.Methods
== [swk mfa]`, `Subject` right, `RecordAssertion` called with counter 0.
- `TestPasskey_DeviceBound` (BE=0, counter step 1): `Methods == [hwk mfa]`, the
  stored counter advanced, `LastUsedAt == now`.
- `TestPasskey_Options`: no `allowCredentials`, `userVerification ==
"required"`; `Conditional` sets `Begun.Mediation == "conditional"`.
- Refusals → `ErrInvalidCredentials`: `_WithoutUserVerification`,
  `_MissingUserHandle`, `_ExpectNamesSubject`, `_TopOrigin` (crossOrigin true +
  topOrigin), `_NonDERSignature` (`RawECDSA`), `_BackupEligibilityChanged`
  (stored BE=0, assertion BE=1), `_RecordAssertionNotApplied` (a store wrapper
  answering `applied=false`), `_StoreFault_EmptyPublicKey`,
  `_StoreFault_ZeroVersion`, `_NotJSON`, `_OversizedResponse`.
- `→ ErrUnknownCredential`: `_UnknownHandle`; `_CredentialNotHeldByHandleOwner`
  (handle of subject A, credential of subject B); `_CredentialOfOtherRPID`.
- `TestPasskey_CounterRegression_DeviceBound`: stored 10, assertion 5 →
  `ErrCloneSuspected`, `CloneSuspectedAt == now`, counter still 10.
- `TestPasskey_ConcurrentReplay_OneWinner`: the same response submitted from 8
  goroutines → exactly one success.
- `TestPasskey_Version1Credential_AdoptsFlags`: a Version 1 credential with
  BE=false stored and an assertion with BE=1 succeeds and leaves
  `Version == CurrentVersion`, BE true; a Version 2 credential in the same
  situation is refused.

- [ ] **Step 2: Run to verify failure** — FAIL.

- [ ] **Step 3: Implement**

Begin: `BeginDiscoverableLogin` (or `BeginDiscoverableMediatedLogin` with
conditional) and `WithUserVerification(Required)`; flow kind passkey, no
subject. Finish: size check → `takeFlow` (refuse a non-empty `e.Subject`) →
parse → `ValidatePasskeyLogin` with a handler that resolves
`handles.Subject(userHandle)`, loads `creds.List(subject, rpID)`, checks rule
3, and returns `errUnknown` when the subject or the credential is missing; a
Version 1 credential gets its adapter BE/BS from the parsed authenticator data
before validation. Map `errUnknown` to `ErrUnknownCredential` (check the
handler error survives go-webauthn's wrapping with `errors.Is`; if it does not,
carry it in a closure variable). `settle`: go-webauthn's `CloneWarning` →
`MarkCloneSuspected` + `ErrCloneSuspected`; `RecordAssertion{PrevSignCount:
stored, SignCount: got, BackupEligible, BackupState, Version: CurrentVersion,
At: now}` must apply; Methods = `hwk` when BE=0 else `swk`, plus `mfa` when the
assertion's UV flag is set.

- [ ] **Step 4: Run to verify pass** — `go test -race ./webauthn/` → PASS.

- [ ] **Step 5: Commit** — `feat(webauthn): discoverable passkey sign-in with clone and replay refusal`

---

### Task 8: Second factor and step-up ceremony

**Files:**

- Create: `webauthn/secondfactor.go`
- Test: `webauthn/secondfactor_test.go`

**Interfaces:**

- Consumes: `settle`, `takeFlow` (Tasks 6-7).
- Produces:

  ```go
  type SecondFactorOptions struct {
      Purpose   string // e.g. "login", "stepup"
      RequireUV bool
  }
  func (rp *RP) BeginSecondFactor(ctx context.Context, flows store.FlowStore, creds CredentialStore, handles HandleStore, subject string, opts SecondFactorOptions) (Begun, error)
  func (rp *RP) FinishSecondFactor(ctx context.Context, flows store.FlowStore, creds CredentialStore, e Expect, response []byte) (Verified, error)
  ```

- [ ] **Step 1: Write the failing tests**

- `TestSecondFactor_WithoutUV`: `Methods == [hwk]` (no `mfa`).
- `TestSecondFactor_WithUV`: `Methods == [hwk mfa]`.
- `TestSecondFactor_Options`: `allowCredentials` holds exactly the subject's
  credential IDs for this RP ID, `userVerification == "preferred"`;
  `RequireUV` makes it `"required"`.
- `TestSecondFactor_RequireUV_RefusesWithoutUV` → `ErrInvalidCredentials`.
- `TestSecondFactor_NoCredentials` → `ErrInvalidCredentials` and no flow written.
- `TestSecondFactor_OtherSubjectsAuthenticator` → `ErrInvalidCredentials`.
- `TestSecondFactor_ExpectWrongSubject` → `ErrInvalidCredentials`.
- `TestSecondFactor_CredentialRemovedMidCeremony` (memory `Delete` between Begin
  and Finish) → `ErrInvalidCredentials`.
- `TestSecondFactor_CounterRegression` → `ErrCloneSuspected`.

- [ ] **Step 2: Run to verify failure** — FAIL.

- [ ] **Step 3: Implement**

Begin: `creds.List`; none → failure without writing a flow; handle via
`handles.Ensure`; `BeginLogin(adapter, WithUserVerification(...))`; flow kind
second_factor with subject and `require_uv`. Finish: `takeFlow` (subject must
equal `e.Subject`, non-empty) → reload `creds.List` → `ValidateLogin`; a
`*protocol.ErrorUnknownCredential` is `ErrInvalidCredentials` here (the caller
already authenticated the subject) → `settle`.

- [ ] **Step 4: Run to verify pass** — `go test -race ./webauthn/` → PASS.

- [ ] **Step 5: Commit** — `feat(webauthn): second-factor and step-up ceremony`

---

### Task 9: `examples/passkeys`

**Files:**

- Create: `examples/passkeys/main.go`, `examples/passkeys/index.html`
- Modify: `.github/workflows/ci.yml` (build-examples job builds
  `./examples/passkeys`)

**Interfaces:**

- Consumes: the whole `webauthn` API and the `authtest` memory stores.

- [ ] **Step 1: Implement**

`net/http` on `localhost:8080`, RP ID `localhost`, origin
`http://localhost:8080`; `//go:embed index.html`; JSON endpoints
`POST /register/begin` (body `{"name"}` — demo only: the name is the subject),
`/register/finish`, `/signin/begin`, `/signin/finish` returning the subject.
The page uses `PublicKeyCredential.parseCreationOptionsFromJSON`,
`parseRequestOptionsFromJSON` and `toJSON()`, offers autofill
(`autocomplete="username webauthn"`, conditional mediation) and a button. A
banner says the stores are in memory and the example is not production code.

- [ ] **Step 2: Verify** — `go build ./examples/passkeys && go vet
./examples/passkeys` → exit 0. Manual: run it, register and sign in with
      Chrome DevTools' WebAuthn virtual authenticator.

- [ ] **Step 3: Commit** — `docs(examples): runnable passkeys example`

---

### Task 10: Coverage floors, mutation check, docs, release

**Files:**

- Modify: `.coverage-floor`, `README.md`, `docs/v2-design.md` (status line),
  `CLAUDE.md`

- [ ] **Step 1: Measure** — `go test -race -covermode=atomic
-coverprofile=coverage.txt ./...`; record each package two to three points
      below its measured value (`examples/passkeys 0`); run the CI awk from
      `.github/workflows/ci.yml` locally → no FAIL lines.

- [ ] **Step 2: Mutation check** — for each design §5.4 check (1-9) and each
      `New` rule, disable it, run `go test ./webauthn/`, confirm a named test fails,
      restore. Record the table (check → failing test) for the PR body.

- [ ] **Step 3: Gates** — `golangci-lint run` (0 issues), `govulncheck ./...`
      (no findings), `go test -race ./...` (PASS).

- [ ] **Step 4: Docs** — README quickstart: `New`, the three ceremony pairs,
      implementing the two stores and running `authtest.WebAuthnStoreSuite` and
      `authtest.FlowStoreSuite`; design status line "G1 implemented".

- [ ] **Step 5: Commit, then ask before pushing** — `docs: v2 G1 readme and
coverage floors`. With the founder's go-ahead: push `v1` and `feat/v2-g1`,
      open the PR (body: what ships, the mutation table, the test commands and
      results, the v1 branch note), let release-please cut `v2.0.0-alpha.1` after
      merge, and remove `release-as` in a follow-up commit.
