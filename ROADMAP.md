# go-auth Product Roadmap

> **Last Updated**: 2025-11-29
> **Version**: 1.0.0
> **Status**: Active Development

This roadmap outlines the strategic direction for go-auth, a comprehensive, modular, and production-ready authentication library for Go applications. Our philosophy is **depth over breadth**—we focus on making authentication exceptionally well rather than adding tangential features.

---

## Table of Contents

- [Executive Summary](#executive-summary)
- [Core Value Proposition](#core-value-proposition)
- [Ideal Customer Profiles](#ideal-customer-profiles)
- [Current State](#current-state)
- [Competitive Positioning](#competitive-positioning)
- [Phased Roadmap](#phased-roadmap)
- [Detailed Feature Analysis](#detailed-feature-analysis)
- [Anti-Roadmap: What We Won't Build](#anti-roadmap-what-we-wont-build)
- [Contributing](#contributing)
- [Changelog](#changelog)

---

## Executive Summary

- **Current State**: go-auth v1.1.1 is a feature-complete authentication library supporting 5 auth methods (Basic, JWT, TOTP, WebAuthn, OIDC), 10+ OAuth providers, compliance-ready audit logging, and storage-agnostic architecture
- **Core Strength**: The only Go library combining all modern auth methods with production-grade audit logging and minimal dependencies
- **Phase 1 Focus**: Enterprise hardening—rate limiting, production storage adapters, and observability integration
- **Phase 2 Focus**: Extended protocol support—SAML, magic links, and additional identity providers
- **Phase 3 Focus**: Platform capabilities—become an identity provider with built-in OIDC server

---

## Core Value Proposition

**go-auth is the comprehensive authentication library for Go developers who need production-ready, compliance-aware authentication without the complexity of full identity platforms.**

Unlike fragmented alternatives that force developers to stitch together OAuth libraries, JWT packages, and session managers, go-auth provides a unified, interface-based architecture where:

- All auth methods share consistent patterns and storage abstractions
- Compliance-ready audit logging is built-in, not bolted-on
- The stdlib-compatible design integrates with any Go HTTP framework
- Minimal dependencies reduce supply chain risk and maintenance burden

The result: developers ship secure authentication in hours, not weeks, while maintaining full control over their data and infrastructure.

---

## Ideal Customer Profiles

### ICP 1: SaaS Backend Developer

**Who they are**: Mid-to-senior Go developers at startups or scale-ups (10-200 employees) building B2B SaaS products. Technically sophisticated, values clean code and minimal dependencies.

**Their context**: Building a new product or service that needs authentication. They want to ship quickly but can't compromise on security. Their users expect modern auth: social login, 2FA, potentially passkeys.

**Jobs to be Done (JTBD)**:
1. Implement secure user authentication without becoming a security expert
2. Support multiple auth methods (password, OAuth, 2FA) without managing multiple libraries
3. Maintain full control of user data (no vendor lock-in to auth services)

**Pain points with alternatives**:
- Goth only does OAuth—still need password auth, JWT, and 2FA separately
- Auth0/Okta have pricing that doesn't scale and create vendor dependency
- Building from scratch takes weeks and risks security mistakes

**What "exceptional" looks like for them**:
- Copy example code, customize storage interface, ship to production in a day
- Add 2FA or WebAuthn later without refactoring existing auth code
- Pass security audits without scrambling to add audit logging

---

### ICP 2: Platform/DevOps Engineer

**Who they are**: Engineers building internal tools, developer platforms, or infrastructure services. They work at tech-forward companies where Go is the standard backend language.

**Their context**: Building internal tooling that needs auth—dashboards, admin panels, APIs. Security and auditability are non-negotiable. May need to integrate with existing identity providers (Okta, Azure AD).

**Jobs to be Done (JTBD)**:
1. Add authentication to internal services quickly
2. Integrate with corporate SSO (OIDC, potentially SAML)
3. Maintain audit trails for compliance and incident investigation

**Pain points with alternatives**:
- Enterprise identity platforms are overkill for internal tools
- Most libraries lack proper audit logging
- SAML support is rare in lightweight Go libraries

**What "exceptional" looks like for them**:
- Plug in corporate Okta/Azure AD in under an hour
- Searchable audit logs for every auth event
- Same library works across all internal services

---

### ICP 3: Enterprise Go Developer

**Who they are**: Developers at larger organizations (500+ employees) in regulated industries—fintech, healthcare, enterprise software. They face compliance requirements (SOC2, HIPAA, PCI-DSS).

**Their context**: Building applications that handle sensitive data. Security isn't optional—it's audited. They need authentication that satisfies compliance frameworks without requiring a dedicated security team.

**Jobs to be Done (JTBD)**:
1. Implement authentication that passes compliance audits
2. Provide audit trails that satisfy SOC2/HIPAA requirements
3. Support enterprise authentication standards (SAML, OIDC)

**Pain points with alternatives**:
- Most libraries treat audit logging as an afterthought
- Compliance features often require expensive enterprise tiers
- DIY solutions require security expertise they may not have

**What "exceptional" looks like for them**:
- Out-of-box audit logging with PII redaction that satisfies auditors
- Clear documentation mapping features to compliance requirements
- WebAuthn/passkey support for phishing-resistant authentication

---

### ICP 4: Startup Technical Founder

**Who they are**: CTOs or technical co-founders at early-stage startups. Time-constrained, wearing multiple hats. Need to ship an MVP but can't cut corners on security.

**Their context**: Racing to validate product-market fit. Authentication is essential but shouldn't consume weeks of development time. They'll likely need to add features (2FA, SSO) as they grow.

**Jobs to be Done (JTBD)**:
1. Ship secure authentication as fast as possible
2. Avoid accumulating technical debt that slows future features
3. Scale auth capabilities as the product grows

**Pain points with alternatives**:
- Full identity platforms are expensive and complex for MVP stage
- Lightweight libraries lack features they'll need at Series A
- Building custom auth creates technical debt

**What "exceptional" looks like for them**:
- Working auth in hours with clear growth path
- Add enterprise features (SSO, 2FA) when customers demand them
- Code they can understand and maintain themselves

---

## Current State

### Fully Implemented

| Component | Description | Package |
|-----------|-------------|---------|
| **Basic Authentication** | Username/password with bcrypt, password reset, email verification | `auth/basic` |
| **JWT Authentication** | Access + refresh tokens, configurable TTLs, revocation support | `auth/jwt` |
| **TOTP 2FA** | RFC 6238 compliant, QR code generation, backup codes | `auth/totp` |
| **WebAuthn/Passkeys** | FIDO2 passwordless authentication, registration and login flows | `auth/webauthn` |
| **OIDC/OAuth2 SSO** | Multi-provider support with CSRF protection | `auth/oidc` |
| **10+ OAuth Providers** | Google, GitHub, Microsoft, GitLab, Auth0, Okta, Apple, Discord, Slack, LinkedIn | `provider` |
| **HTTP Middleware** | Basic, JWT, and Session middleware; stdlib compatible | `middleware` |
| **Session Management** | Secure session handling with TTL management | `session` |
| **Audit Logging** | SOC2/GDPR/HIPAA compliant, PII redaction, 19+ event types | `audit` |
| **Storage Interfaces** | UserStore, CredentialStore, SessionStore, TokenStore, OIDCStateStore | `storage` |
| **In-Memory Storage** | Development/testing implementations for all interfaces | `storage` |
| **Complete Example** | Full-featured example with PostgreSQL schema | `examples/complete` |

### Not Yet Implemented

| Feature | Demand | Notes |
|---------|--------|-------|
| Rate Limiting Middleware | High | Mentioned in README roadmap |
| SAML Support | Medium | Enterprise requirement |
| Built-in OIDC Provider/Server | Medium | Become an IdP, not just consume |
| Production Storage Adapters | High | PostgreSQL, MySQL, Redis packages |
| Additional SSO Providers | Low | AWS Cognito, Keycloak, custom |

---

## Competitive Positioning

### Current Landscape

| Alternative | Strengths | Weaknesses | go-auth Advantage |
|-------------|-----------|------------|-------------------|
| **[Goth](https://github.com/markbates/goth)** | Simple OAuth/OAuth2, 30+ providers, idiomatic Go | OAuth only—no password auth, JWT, 2FA, WebAuthn, or audit logging | Complete auth solution vs. OAuth-only |
| **[Authboss](https://github.com/volatiletech/authboss)** | Full-featured, modular, mature | Heavy/framework-like, fewer OIDC providers, no WebAuthn, dated | Lighter weight, modern auth methods, better OIDC |
| **[Casbin](https://github.com/casbin/casbin)** | Powerful authorization (RBAC/ABAC) | Authorization only—not authentication | Different category; complementary |
| **[go-oidc](https://github.com/coreos/go-oidc)** | Solid OIDC client, widely adopted | OIDC only—no other auth methods | Multi-method authentication |
| **[zitadel/oidc](https://github.com/zitadel/oidc)** | OIDC client + server capability | OIDC-specific, no other auth methods | Broader auth method coverage |
| **Auth0/Okta SDKs** | Enterprise features, managed service | Vendor lock-in, pricing scales poorly, data sovereignty concerns | Self-hosted, no vendor dependency |

### Our Moat

1. **Unified Architecture**: Single library for all auth methods with consistent patterns
2. **Storage Agnostic**: Interface-based design works with any database
3. **Compliance Built-In**: Audit logging isn't an afterthought—it's core
4. **Minimal Dependencies**: Reduced supply chain risk; easier security audits
5. **Stdlib Compatible**: Works with any Go HTTP framework

### Positioning Statement

> For Go developers who need secure, production-ready authentication, **go-auth** is the comprehensive authentication library that provides all modern auth methods with compliance-ready audit logging, unlike fragmented alternatives like Goth (OAuth only) or managed services like Auth0 (vendor lock-in), which force tradeoffs between completeness, control, and cost.

---

## Phased Roadmap

### Phase 1: Enterprise Hardening

**Outcome**: go-auth becomes the default choice for production Go applications with enterprise-grade reliability and observability.

**Target ICPs**: Enterprise Go Developer, Platform/DevOps Engineer

| Priority | Feature | Score | Effort | Status | Notes |
|----------|---------|-------|--------|--------|-------|
| P0 | Rate Limiting Middleware | 9.1 | M | Planned | Per-user, per-IP, configurable strategies |
| P0 | PostgreSQL Storage Adapter | 8.9 | M | Planned | Reference implementation with migrations |
| P1 | Redis Session/Token Store | 8.5 | S | Planned | High-performance ephemeral storage |
| P1 | OpenTelemetry Integration | 8.2 | S | Planned | Tracing and metrics for auth operations |
| P2 | MySQL Storage Adapter | 7.4 | M | Planned | Alternative to PostgreSQL |
| P2 | Prometheus Metrics | 7.1 | S | Planned | Auth operation metrics export |

---

### Phase 2: Extended Protocol Support

**Outcome**: go-auth supports enterprise SSO requirements and modern passwordless flows, removing blockers for regulated industries.

**Target ICPs**: Enterprise Go Developer, Platform/DevOps Engineer, SaaS Backend Developer

| Priority | Feature | Score | Effort | Status | Notes |
|----------|---------|-------|--------|--------|-------|
| P0 | SAML 2.0 Service Provider | 8.7 | L | Planned | Enterprise SSO requirement |
| P1 | Magic Link Authentication | 8.3 | M | Planned | Passwordless email auth |
| P1 | AWS Cognito Provider | 7.8 | S | Planned | Common enterprise IdP |
| P2 | Keycloak Provider | 7.2 | S | Planned | Popular open-source IdP |
| P2 | LDAP Authentication | 6.9 | M | Planned | Legacy enterprise systems |
| P3 | Passkey-Only Registration | 6.5 | S | Planned | True passwordless accounts |

---

### Phase 3: Platform Capabilities

**Outcome**: go-auth can serve as an identity provider, enabling applications to issue tokens to other services and supporting multi-tenant architectures.

**Target ICPs**: Platform/DevOps Engineer, SaaS Backend Developer (at scale)

| Priority | Feature | Score | Effort | Status | Notes |
|----------|---------|-------|--------|--------|-------|
| P0 | OIDC Provider/Server | 8.4 | XL | Planned | Become an IdP |
| P1 | Multi-Tenancy Support | 7.9 | L | Planned | Tenant-scoped users and sessions |
| P1 | API Key Authentication | 7.6 | M | Planned | Machine-to-machine auth |
| P2 | OAuth2 Authorization Server | 7.3 | L | Planned | Issue tokens to third parties |
| P2 | Device Authorization Flow | 6.8 | M | Planned | IoT/CLI device auth |
| P3 | User Impersonation | 6.2 | S | Planned | Admin support workflows |

---

## Detailed Feature Analysis

### Tier 1: Critical (P0 Features)

#### Rate Limiting Middleware

**Score**: 9.1/10

**Why it matters**: Every ICP needs protection against brute-force attacks. Currently, users must bring their own rate limiting, creating friction and potential security gaps. This is the most requested missing feature.

| Pros | Cons |
|------|------|
| Essential security feature for any production deployment | Adds complexity to middleware configuration |
| High demand from all ICPs | Requires consideration of distributed deployments |
| Natural extension of existing middleware package | State storage for distributed rate limiting |
| Differentiator vs. Goth and basic auth libraries | |

**Current State**: Not implemented. Users currently integrate external rate limiting (e.g., `golang.org/x/time/rate`).

**Implementation Approach**:
- Add `middleware/ratelimit` package with configurable strategies
- Support per-user, per-IP, per-endpoint limiting
- Interface-based storage for distributed deployments (memory, Redis)
- Integrate with audit logging for rate limit events
- Provide sensible defaults (e.g., 5 login attempts per minute per IP)

**Success Criteria**:
- Rate limiting works out-of-box with in-memory storage
- Redis adapter available for distributed deployments
- Rate limit events appear in audit logs
- Configurable response (429 status, retry-after header)

---

#### PostgreSQL Storage Adapter

**Score**: 8.9/10

**Why it matters**: In-memory storage is only suitable for development. Every production deployment needs persistent storage. PostgreSQL is the most common choice for Go applications, and providing a reference implementation accelerates adoption.

| Pros | Cons |
|------|------|
| Unblocks production deployments | Adds database dependency for adapter users |
| Reference implementation helps users build custom adapters | Migration management considerations |
| PostgreSQL is Go ecosystem standard | May encourage tight coupling if not careful |
| Complete example already has PostgreSQL schema | |

**Current State**: `examples/complete` contains PostgreSQL implementations, but they're not packaged for reuse.

**Implementation Approach**:
- Create `storage/postgres` package
- Extract and refine implementations from `examples/complete`
- Use `database/sql` with `lib/pq` for minimal dependencies
- Provide SQL migrations as embedded files
- Support connection pooling configuration
- Include comprehensive integration tests

**Success Criteria**:
- Users can `import "github.com/meysam81/go-auth/storage/postgres"` and connect
- Migrations handle schema creation and versioning
- Performance matches or exceeds in-memory for read operations
- Integration tests run in CI with containerized PostgreSQL

---

#### SAML 2.0 Service Provider

**Score**: 8.7/10

**Why it matters**: Many enterprises require SAML for SSO. Its absence blocks go-auth adoption in regulated industries and larger organizations. This is explicitly requested in the README roadmap.

| Pros | Cons |
|------|------|
| Unlocks enterprise market segment | SAML is complex and XML-heavy |
| Required for many compliance frameworks | Larger implementation effort than OIDC providers |
| Limited competition in Go SAML libraries | Security-sensitive code requires extra care |
| Requested in existing roadmap | Testing requires SAML IdP setup |

**Current State**: Not implemented. Listed as roadmap item.

**Implementation Approach**:
- Create `auth/saml` package using `github.com/crewjam/saml` as foundation
- Implement SP-initiated SSO flow
- Support metadata exchange (both file and URL)
- Map SAML assertions to go-auth User model
- Integrate with existing audit logging
- Provide configuration for common IdPs (Okta, Azure AD, Google Workspace)

**Success Criteria**:
- Users can authenticate via enterprise SAML IdPs
- Works with Azure AD, Okta, and Google Workspace
- SAML authentication events appear in audit logs
- Metadata endpoint for IdP configuration

---

### Tier 2: High Value (P1 Features)

#### Redis Session/Token Store

**Score**: 8.5/10

**Why it matters**: Sessions and tokens are ephemeral data that benefit from Redis's performance characteristics. This is essential for horizontally scaled deployments.

| Pros | Cons |
|------|------|
| Essential for horizontal scaling | Adds Redis dependency |
| Natural fit for TTL-based data | Requires Redis infrastructure |
| High performance for session validation | |
| Common production pattern | |

**Current State**: Not implemented. Users must implement `SessionStore` and `TokenStore` interfaces.

**Implementation Approach**:
- Create `storage/redis` package
- Implement `SessionStore`, `TokenStore`, `OIDCStateStore`
- Use `github.com/redis/go-redis` client (widely adopted, maintained)
- Support Redis Cluster and Sentinel configurations
- Provide connection pooling and timeout configuration
- Include TTL handling aligned with go-auth semantics

**Success Criteria**:
- Session validation under 1ms for cache hits
- Automatic TTL expiration matches go-auth session semantics
- Works with Redis Cluster for high availability
- Connection pool management handles load spikes

---

#### Magic Link Authentication

**Score**: 8.3/10

**Why it matters**: Passwordless authentication via email is increasingly popular. It eliminates password management burden while providing good security for many use cases.

| Pros | Cons |
|------|------|
| Modern, user-friendly auth method | Requires email delivery infrastructure |
| Reduces password-related support burden | Security depends on email account security |
| Natural extension of existing email verification | Link expiration UX considerations |
| Differentiator vs. competitors | |

**Current State**: Email verification tokens exist in `auth/basic`. Magic link would extend this pattern.

**Implementation Approach**:
- Create `auth/magiclink` package
- Leverage existing `CredentialStore` token storage
- Configurable link TTL (default: 15 minutes)
- One-time use tokens with automatic invalidation
- Integration with audit logging
- Provide email template recommendations

**Success Criteria**:
- Users can authenticate without password
- Links expire after configurable duration
- Each link works exactly once
- Clear audit trail for magic link events

---

#### OpenTelemetry Integration

**Score**: 8.2/10

**Why it matters**: Observability is non-negotiable for production systems. OpenTelemetry is the industry standard, and first-class support differentiates go-auth from libraries that treat observability as an afterthought.

| Pros | Cons |
|------|------|
| Industry-standard observability | Adds optional dependency |
| Tracing aids debugging auth issues | Configuration complexity |
| Metrics enable alerting on auth anomalies | |
| Professional, enterprise expectation | |

**Current State**: Not implemented. Audit logging provides events but not distributed tracing.

**Implementation Approach**:
- Add optional `go.opentelemetry.io/otel` integration
- Trace spans for authentication operations
- Counters for auth success/failure rates
- Histograms for authentication latency
- Connect trace IDs to audit log entries
- Zero overhead when not configured

**Success Criteria**:
- Auth operations appear in distributed traces
- Dashboards can show auth success rates and latencies
- Trace IDs link audit logs to request traces
- No performance impact when OTel not configured

---

### Tier 3: Strategic (P2 Features)

#### Multi-Tenancy Support

**Score**: 7.9/10

**Why it matters**: B2B SaaS applications commonly need tenant isolation. Native support simplifies a complex requirement.

| Pros | Cons |
|------|------|
| Critical for B2B SaaS | Increases complexity across all components |
| Difficult to add retroactively | Storage schema implications |
| Differentiator for enterprise segment | Testing matrix expands significantly |

**Current State**: Not implemented. Users handle tenancy in their storage implementations.

**Implementation Approach**:
- Add `TenantID` field to relevant models
- Tenant-scoped queries in storage interfaces
- Middleware for tenant extraction from request
- Audit logs include tenant context
- Backward compatible (single-tenant = default tenant)

**Success Criteria**:
- Users isolated by tenant without custom code
- Tenant context flows through all operations
- Clear upgrade path from single to multi-tenant

---

#### API Key Authentication

**Score**: 7.6/10

**Why it matters**: Machine-to-machine authentication is essential for APIs. API keys are simpler than OAuth for internal services and programmatic access.

| Pros | Cons |
|------|------|
| Essential for M2M and API access | Security model differs from user auth |
| Simpler than OAuth for internal services | Key rotation and revocation complexity |
| Common production requirement | |

**Current State**: Not implemented. Users use JWT or custom solutions.

**Implementation Approach**:
- Create `auth/apikey` package
- Secure key generation with configurable prefix
- Key hashing (never store plaintext)
- Scopes/permissions support
- Key rotation without downtime
- Rate limiting per key

**Success Criteria**:
- Developers can issue and revoke API keys
- Keys support scoped permissions
- Key usage appears in audit logs
- Rotation flow documented and tested

---

### Tier 4: Future Consideration (P3 Features)

#### OIDC Provider/Server

**Score**: 8.4/10 (high value but high effort)

**Why it matters**: Enables go-auth applications to become identity providers, issuing tokens to other applications. This is transformative but requires significant implementation effort.

| Pros | Cons |
|------|------|
| Transformative capability | XL effort, complexity |
| Opens new use cases (platform as IdP) | Certification requirements for compliance |
| Strategic differentiation | Ongoing maintenance burden |

**Current State**: Not implemented. Listed as "nice to have" in README.

**Implementation Approach**:
- Build on `zitadel/oidc` library or implement from spec
- Support authorization code and client credentials flows
- Token introspection endpoint
- User info endpoint
- Dynamic client registration (optional)
- Consider OpenID certification

**Success Criteria**:
- Applications can authenticate users against go-auth instance
- Standard OIDC clients work without modification
- Clear documentation for IdP deployment

---

## Anti-Roadmap: What We Won't Build

Explicitly defining what we won't build protects focus and sets clear expectations.

### User Interface / Admin Dashboard

**Why not**: go-auth is a library, not an application. UI creates maintenance burden, opinionated design choices, and framework coupling. Users should build UIs suited to their applications.

### Email Delivery

**Why not**: Email infrastructure is complex and orthogonal to authentication. Users should integrate their preferred email service (SendGrid, SES, Postmark). We provide templates and hooks, not delivery.

### SMS/Phone Verification

**Why not**: Phone verification requires carrier integrations, regional compliance, and ongoing costs. TOTP provides superior 2FA. If phone verification is needed, users integrate Twilio/Vonage.

### Social Features (friends, followers, etc.)

**Why not**: Out of scope. We do authentication (who you are), not social graphs (who you know).

### Payment/Subscription Integration

**Why not**: Billing is a separate domain. Authentication should not be coupled to payment state. Users integrate Stripe or similar independently.

### Full Identity Platform (self-contained IdP)

**Why not**: We provide OIDC server capability (Phase 3), but we're not building Keycloak or Ory. Users needing a complete IdP should use those projects. go-auth remains a library for embedding auth in applications.

### Breaking Backward Compatibility

**Why not**: Stability is a feature. We follow semantic versioning strictly. Breaking changes only in major versions with migration guides.

### Closed-Source / Enterprise Edition

**Why not**: The full library remains open source. Trust and adoption depend on transparency. Sustainable through sponsorship, not feature gating.

---

## Contributing

We welcome contributions aligned with this roadmap. Here's how to get involved:

### Picking Up Roadmap Items

1. **Check existing issues**: Look for issues tagged `roadmap` or the specific feature
2. **Comment your intent**: Let maintainers know you're working on something
3. **Start small**: First contribution? Pick a P2 or P3 item to learn the codebase
4. **Follow the patterns**: Review existing packages for consistent style

### Contribution Guidelines

- Follow the [Google Go Style Guide](https://google.github.io/styleguide/go/)
- Add tests for new functionality
- Update documentation for public APIs
- Keep dependencies minimal
- Ensure audit logging for security-relevant operations

### High-Impact Contribution Opportunities

| Feature | Effort | Impact | Good First Issue |
|---------|--------|--------|------------------|
| Redis Storage Adapter | S | High | No |
| Prometheus Metrics | S | Medium | Yes |
| Additional OAuth Providers | S | Low | Yes |
| MySQL Storage Adapter | M | Medium | No |
| Documentation Improvements | XS | Medium | Yes |

### Proposing New Features

Before implementing features not on this roadmap:

1. Open a discussion issue explaining the use case
2. Connect the feature to a specific ICP and JTBD
3. Explain why it strengthens (not dilutes) the core value proposition
4. Be prepared for "not now" or "not ever"—focus is a feature

---

## Changelog

### Roadmap v1.0.0 (2025-11-29)

- Initial roadmap document
- Defined 4 ICPs with JTBD
- Established 3-phase roadmap structure
- Documented competitive positioning
- Created anti-roadmap for explicit scope boundaries

---

*This roadmap is a living document. It reflects current understanding and priorities, which may evolve based on community feedback and market needs.*
