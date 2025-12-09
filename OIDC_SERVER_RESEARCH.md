# OIDC Server Implementation Research: Feasibility Analysis for go-auth

> **Date**: 2025-12-09
> **Status**: Research Complete
> **Recommendation**: **Proceed with Caution** - Use `zitadel/oidc` as foundation, not build from scratch

---

## Executive Summary

After comprehensive research into OIDC server (Identity Provider) implementation for go-auth, I recommend **against building an OIDC server from scratch** but **support integrating with the certified `zitadel/oidc` library** as an optional, well-isolated module.

### Key Findings

| Factor | Assessment | Risk Level |
|--------|------------|------------|
| Technical Feasibility | Achievable via `zitadel/oidc` | Medium |
| Security Risk | High if built from scratch | High |
| Maintenance Burden | Significant ongoing commitment | High |
| Strategic Fit | Marginal - serves niche use case | Medium |
| Scope Estimation | XL effort (roadmap accurate) | High |

---

## 1. OIDC Server Specification Requirements

### Required Endpoints (OIDC Core 1.0)

An OpenID Provider must implement these endpoints per the [OpenID Connect Core 1.0 specification](https://openid.net/specs/openid-connect-core-1_0.html):

| Endpoint | Required | Purpose |
|----------|----------|---------|
| Authorization Endpoint | Yes | Initiates authentication, returns authorization code |
| Token Endpoint | Yes | Exchanges code for tokens (access, ID, refresh) |
| UserInfo Endpoint | Yes | Returns claims about authenticated user |
| JWKS Endpoint | Yes | Publishes signing keys for token verification |
| Discovery Endpoint | Recommended | `/.well-known/openid-configuration` metadata |
| Revocation Endpoint | Optional | Token revocation |
| Introspection Endpoint | Optional | Token introspection |
| End Session Endpoint | Optional | Logout/session termination |

### Required Flows

At minimum, an OIDC server should support:
- **Authorization Code Flow** (most secure, recommended)
- **PKCE Extension** (required for public clients per OAuth 2.1)
- **Client Credentials Flow** (machine-to-machine)

Optional but commonly expected:
- Implicit Flow (deprecated but some legacy clients require it)
- Hybrid Flow
- Device Authorization Flow
- Refresh Token Grant

### Token Requirements

- **ID Tokens**: Must be signed JWTs with specific claims (`iss`, `sub`, `aud`, `exp`, `iat`, `nonce`)
- **Access Tokens**: Can be opaque or JWT, must support scopes
- **Refresh Tokens**: Secure, rotatable, revocable

---

## 2. Architecture Compatibility Analysis

### Current go-auth Architecture Strengths

The existing go-auth architecture has several components that could be reused:

| Component | Reusability | Notes |
|-----------|-------------|-------|
| `auth/jwt` | **High** | Token generation/validation patterns exist |
| `storage/` interfaces | **Medium** | Needs extension for clients, grants |
| `session/` | **Medium** | Challenge/state management patterns |
| `audit/` | **High** | Compliance logging ready |
| `middleware/` | **Low** | Designed for RP, not OP |

### New Components Required for OIDC Server

Based on [`zitadel/oidc` package interfaces](https://pkg.go.dev/github.com/zitadel/oidc/v3/pkg/op):

```
New Storage Interfaces:
├── ClientStore          # OAuth2 client registration/lookup
├── AuthRequestStore     # Authorization request persistence
├── TokenStore           # Issued tokens (access, refresh, ID)
├── KeyStore             # Signing keys (JWKS)
├── SessionStore         # User sessions across clients
├── ConsentStore         # User consent records
└── DeviceCodeStore      # Device flow codes (optional)

New Core Components:
├── AuthorizationServer  # Core OP logic
├── TokenService         # Token minting with proper claims
├── KeyManager           # RSA/EC key rotation
├── ConsentHandler       # User consent UI integration
├── ClientValidator      # Client authentication methods
└── ScopeHandler         # Scope validation and mapping
```

### Gap Analysis

| Requirement | Current State | Gap |
|-------------|---------------|-----|
| Client Management | Not implemented | **Large** - Need full OAuth2 client registry |
| Key Management | Basic (symmetric JWT) | **Large** - Need asymmetric keys, rotation, JWKS |
| Authorization Flows | N/A (client-side only) | **Large** - Complete implementation needed |
| Consent Management | N/A | **Medium** - Needs UI integration hooks |
| Token Introspection | N/A | **Medium** - New endpoint |
| Discovery | N/A | **Small** - Metadata generation |

---

## 3. Existing Go OIDC Server Libraries

### Comparison Matrix

| Library | Type | Certification | Complexity | Best For |
|---------|------|---------------|------------|----------|
| [zitadel/oidc](https://github.com/zitadel/oidc) | Library | **RP Certified** | Medium | Embedding in Go apps |
| [ory/fosite](https://github.com/ory/fosite) | Low-level SDK | Used by Hydra | High | Custom OAuth2/OIDC |
| [ory/hydra](https://github.com/ory/hydra) | Standalone service | **OpenID Certified** | Low (ops) | Production IdP service |
| Keycloak | Full IAM | **OpenID Certified** | Low (ops) | Enterprise IAM |

### zitadel/oidc: Recommended Foundation

**Why zitadel/oidc is the right choice for go-auth:**

1. **Certified RP** - Already passed OpenID Foundation conformance testing
2. **Library, not service** - Embeddable in applications (matches go-auth philosophy)
3. **Uses standard Go OAuth2** - Builds on `golang.org/x/oauth2` (already a go-auth dependency)
4. **Proven in production** - Powers ZITADEL's identity platform
5. **Active maintenance** - Regular updates, security patches

**Trade-offs:**
- Adds a significant dependency
- Still requires implementing storage interfaces
- Not yet certified as OP (only RP)

### ory/fosite: Alternative Consideration

Per the [fosite documentation](https://github.com/ory/fosite):
- More low-level, requires implementing many handlers
- Does not use standard Go OAuth2 package (divergent approach)
- Better suited for building Hydra-like services

---

## 4. Security Risk Analysis

### Critical Security Concerns

Building an OIDC server introduces attack surface that doesn't exist in a client-only library:

| Vulnerability Class | Risk | Mitigation |
|---------------------|------|------------|
| [Token Injection/Forgery](https://security.lauritz-holtmann.de/post/sso-security-overview/) | **Critical** | Proper signature validation, key rotation |
| [SSRF via request_uri](https://security.lauritz-holtmann.de/post/sso-security-overview/) | **High** | Disable or strictly validate request_uri |
| [Redirect URI Manipulation](https://www.vaadata.com/blog/understanding-oauth-2-0-and-its-common-vulnerabilities/) | **High** | Strict URI validation, no wildcards |
| [Authorization Code Interception](https://guptadeepak.com/security-vulnerabilities-in-saml-oauth-2-0-openid-connect-and-jwt/) | **High** | PKCE mandatory, short-lived codes |
| [Session Fixation](https://www.slashid.dev/blog/oauth-security/) | **Medium** | Proper session binding |
| [Mix-Up Attacks](https://guptadeepak.com/security-vulnerabilities-in-saml-oauth-2-0-openid-connect-and-jwt/) | **Medium** | Issuer validation, state binding |

### Recent CVEs in OIDC Implementations (2025)

- **CVE-2025-54603**: Authentication bypass in Claroty SRA due to incorrect OIDC flow implementation - allowed admin user creation and MFA bypass
- Multiple Identity Providers vulnerable to SSRF via request_uri parameter

### Security Maintenance Burden

An OIDC server requires:
- Ongoing security monitoring for protocol-level vulnerabilities
- Cryptographic key rotation procedures
- Regular dependency updates for crypto libraries
- Security audit budget (estimated $10K-50K annually for serious deployments)

**Verdict**: Building from scratch is **inadvisable** due to security complexity. Using a certified library like zitadel/oidc significantly reduces risk.

---

## 5. OpenID Certification Considerations

### Certification Requirements

Per the [OpenID Foundation](https://openid.net/certification/):

| Profile | Testing | Fee (Members) | Fee (Non-Members) |
|---------|---------|---------------|-------------------|
| Basic OP | Required | $700/year | $3,500/year |
| Config OP | Required | Included | Included |
| Dynamic OP | Optional | Included | Included |
| FAPI | Optional | $1,000/year | $5,000/year |

### Should go-auth Pursue Certification?

**Arguments For:**
- Increases trust and adoption
- Marketing differentiation
- Forces rigorous testing

**Arguments Against:**
- Ongoing cost (~$700-1000/year)
- Maintenance commitment to pass future tests
- zitadel/oidc already certified (can leverage)

**Recommendation**: Don't pursue independent certification initially. Use certified zitadel/oidc as foundation and document that lineage.

---

## 6. Strategic Fit Analysis

### Does OIDC Server Fit go-auth's Value Proposition?

**Current Value Proposition** (from ROADMAP.md):
> "go-auth is the comprehensive authentication library for Go developers who need production-ready, compliance-aware authentication **without the complexity of full identity platforms**."

| Consideration | Assessment |
|---------------|------------|
| **Adds complexity** | Yes - significantly |
| **Serves core ICPs** | Partially - niche use case |
| **Maintains minimal deps** | No - adds zitadel/oidc (~significant) |
| **Follows library philosophy** | Yes - if implemented as optional module |

### Target Use Cases

Who would actually use go-auth as an OIDC server?

1. **Platform developers** building multi-tenant SaaS who need to issue tokens to tenant applications
2. **API gateway operators** needing embedded token issuance
3. **DevOps teams** wanting lightweight IdP for internal tools (vs. Keycloak overhead)

**Market Size**: Small. Most users needing an IdP choose Keycloak, Ory Hydra, or managed services.

### Competitive Positioning Impact

| If Implemented | Positive | Negative |
|----------------|----------|----------|
| Differentiation | Only Go auth library with client+server | Scope creep, maintenance burden |
| Adoption | May attract platform developers | May confuse core audience |
| Trust | Enhanced if certified | Damaged if security issues |

---

## 7. Implementation Approaches

### Option A: Don't Implement (Recommended Alternative Path)

Instead of building OIDC server capability:

1. **Document integration patterns** with Ory Hydra/Keycloak
2. **Provide storage adapters** that work with external IdPs
3. **Focus roadmap** on Phase 1 (rate limiting, storage adapters) and Phase 2 (SAML, magic links)

**Pros**: Lower risk, focused scope, faster delivery of higher-value features
**Cons**: Doesn't address "become an IdP" use case

### Option B: Thin Wrapper Around zitadel/oidc (Recommended if Proceeding)

Create `auth/oidcserver` package that:
1. Wraps zitadel/oidc with go-auth's storage interface patterns
2. Integrates with existing audit logging
3. Provides opinionated defaults for common use cases
4. Remains clearly marked as **experimental/beta**

```go
// Example API shape
package oidcserver

type Config struct {
    Issuer          string
    Storage         Storage  // Maps to zitadel/oidc interfaces
    KeyProvider     KeyProvider
    AuditLogger     audit.AuditLogger
    AllowedClients  []ClientConfig
}

func NewProvider(cfg Config) (*Provider, error)
```

**Pros**: Leverages certified code, reduces security risk
**Cons**: Adds significant dependency, still substantial work

### Option C: Full Custom Implementation (Not Recommended)

Build OIDC server from scratch using ory/fosite or raw implementation.

**Pros**: Maximum control
**Cons**: Massive scope, high security risk, years of maintenance

---

## 8. Effort Estimation

### Option B (zitadel/oidc Wrapper) Breakdown

| Component | Effort | Notes |
|-----------|--------|-------|
| Storage interface adapters | 2-3 weeks | Map go-auth storage to zitadel interfaces |
| Key management | 1-2 weeks | JWKS generation, rotation |
| Audit integration | 1 week | Wrap operations with audit events |
| Configuration/defaults | 1 week | Sensible defaults for common cases |
| HTTP handlers | 1-2 weeks | Route setup, error handling |
| Testing | 2-3 weeks | Unit + integration + conformance |
| Documentation | 1-2 weeks | Usage docs, security considerations |
| **Total** | **10-16 weeks** | Single experienced developer |

**Roadmap Assessment**: The "XL" effort rating is accurate.

---

## 9. Recommendations

### Primary Recommendation

**Defer OIDC server implementation** in favor of higher-value Phase 1 and Phase 2 features:
- Rate limiting middleware (P0)
- PostgreSQL/Redis storage adapters (P0)
- SAML 2.0 SP (P0)
- Magic link authentication (P1)

These features serve more users with less risk.

### Secondary Recommendation (If Proceeding)

If the decision is made to implement OIDC server capability:

1. **Use zitadel/oidc as foundation** - don't build from scratch
2. **Create separate module** - `github.com/meysam81/go-auth/oidcserver` with its own go.mod
3. **Mark as experimental** - clear documentation that this is beta
4. **Limit initial scope**:
   - Authorization Code + PKCE only
   - No Implicit/Hybrid flows
   - No Device flow initially
   - No dynamic client registration
5. **Require explicit opt-in** - don't auto-include in main module
6. **Budget for security review** - external audit before v1.0

### What Not To Do

- **Don't build from scratch** - the security risk is too high
- **Don't pursue OpenID certification immediately** - wait for production validation
- **Don't add to core module** - keep as optional separate package
- **Don't promise compatibility** with all OIDC features initially

---

## 10. Conclusion

Implementing an OIDC server is technically feasible for go-auth, but it represents a **significant expansion of scope** with **meaningful security risks**. The existing Go ecosystem already has excellent certified solutions (zitadel/oidc, Ory Hydra).

The strategic question is: **Should go-auth become a platform (client + server) or remain focused as the best authentication client library?**

My recommendation is to **remain focused** unless there's clear user demand that justifies the maintenance burden and security responsibility of operating identity provider code.

---

## Sources

- [OpenID Connect Core 1.0 Specification](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OpenID Foundation Certification](https://openid.net/certification/)
- [OpenID Certification Fees](https://openid.net/certification/fees/)
- [zitadel/oidc GitHub](https://github.com/zitadel/oidc)
- [ory/fosite GitHub](https://github.com/ory/fosite)
- [ory/hydra GitHub](https://github.com/ory/hydra)
- [Real-life OIDC Security Overview](https://security.lauritz-holtmann.de/post/sso-security-overview/)
- [OAuth 2.0 Common Vulnerabilities](https://www.vaadata.com/blog/understanding-oauth-2-0-and-its-common-vulnerabilities/)
- [SSO Protocol Security Vulnerabilities 2025](https://guptadeepak.com/security-vulnerabilities-in-saml-oauth-2-0-openid-connect-and-jwt/)
- [OAuth Security Best Practices](https://www.slashid.dev/blog/oauth-security/)
- [zitadel/oidc pkg.go.dev](https://pkg.go.dev/github.com/zitadel/oidc/v3/pkg/op)
