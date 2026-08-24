// Package audit provides audit logging interfaces and implementations for authentication events.
// This package enables compliance with modern security standards (SOC2, GDPR, HIPAA, PCI-DSS)
// by providing comprehensive audit trails of authentication and authorization events.
package audit

import (
	"context"
	"log"
	"time"
)

// AuditLogger defines the interface for audit logging.
// Implementations should handle structured logging of security events in a compliance-ready format.
//
// The name stutters, but renaming an exported type breaks every downstream
// implementation, so it stands until v2 renames it to Logger.
//
//nolint:revive // Renaming an exported type is a breaking change; deferred to v2.
type AuditLogger interface {
	// Log records an audit event. Implementations must be thread-safe.
	// Returns an error if the event cannot be logged, though logging failures
	// should not prevent the operation from completing.
	Log(ctx context.Context, event *AuditEvent) error
}

// LogErrorHandler is notified when an AuditLogger rejects an event.
//
// An audit sink that fails is itself a security-relevant condition: for a
// package whose purpose is compliance evidence, a record that was never written
// and never reported is indistinguishable from an event that never happened.
// The handler must not block and must not panic; it runs inline on the
// request's goroutine, after the wrapped operation has completed.
type LogErrorHandler func(ctx context.Context, event *AuditEvent, err error)

// DefaultLogErrorHandler reports a dropped audit event on the standard
// library's default logger.
//
// It deliberately prints only the event type and result. The event itself
// carries the actor's email, username and source address, and an error path is
// the last place that should be the one component writing unredacted PII to a
// destination the RedactionConfig does not cover.
func DefaultLogErrorHandler(_ context.Context, event *AuditEvent, err error) {
	if event == nil {
		log.Printf("go-auth/audit: audit event dropped: %v", err)
		return
	}
	log.Printf("go-auth/audit: audit event %s (%s) dropped: %v", event.EventType, event.EventResult, err)
}

// EventType represents the type of audit event.
type EventType string

// The event vocabulary. These identifiers are the stable part of this package:
// v2 keeps them and removes the wrappers that emit them (F-22), so an
// application decorating its own call sites should reuse these values rather
// than inventing parallel strings that a log pipeline then has to reconcile.
const (
	// EventAuthLogin records a credential verification attempt.
	EventAuthLogin EventType = "auth.login"

	// EventAuthLogout records a session being ended by its owner.
	EventAuthLogout EventType = "auth.logout"

	// EventAuthRegister records an account being created.
	EventAuthRegister EventType = "auth.register"

	// EventAuthPasswordChange records an authenticated password change.
	EventAuthPasswordChange EventType = "auth.password_change"

	// EventAuthPasswordReset records a password set through the reset flow,
	// which is the unauthenticated path and therefore the higher-value one.
	EventAuthPasswordReset EventType = "auth.password_reset"

	// EventTokenGenerate records a token being minted.
	EventTokenGenerate EventType = "token.generate"

	// EventTokenValidate records a token being presented for verification.
	EventTokenValidate EventType = "token.validate"

	// EventTokenRefresh records an access token minted from a refresh token.
	EventTokenRefresh EventType = "token.refresh"

	// EventTokenRevoke records a token being revoked.
	EventTokenRevoke EventType = "token.revoke"

	// EventSessionCreate records a session being established.
	EventSessionCreate EventType = "session.create"

	// EventSessionValidate records a session identifier being presented.
	EventSessionValidate EventType = "session.validate"

	// EventSessionRefresh records a session's expiry being extended.
	EventSessionRefresh EventType = "session.refresh"

	// EventSessionDelete records a session being destroyed.
	EventSessionDelete EventType = "session.delete"

	// EventWebAuthnRegisterBegin records the start of a registration ceremony.
	EventWebAuthnRegisterBegin EventType = "webauthn.register.begin"

	// EventWebAuthnRegisterFinish records the completion of a registration
	// ceremony.
	EventWebAuthnRegisterFinish EventType = "webauthn.register.finish"

	// EventWebAuthnLoginBegin records the start of an assertion ceremony.
	EventWebAuthnLoginBegin EventType = "webauthn.login.begin"

	// EventWebAuthnLoginFinish records the completion of an assertion ceremony.
	EventWebAuthnLoginFinish EventType = "webauthn.login.finish"

	// EventOIDCAuthorize records an authorization request being started.
	EventOIDCAuthorize EventType = "oidc.authorize"

	// EventOIDCCallback records a callback being received from the provider.
	EventOIDCCallback EventType = "oidc.callback"

	// EventOIDCExchange records an authorization code being exchanged.
	EventOIDCExchange EventType = "oidc.token_exchange"

	// EventUserCreate records a user record being created.
	EventUserCreate EventType = "user.create"

	// EventUserUpdate records a user record being modified.
	EventUserUpdate EventType = "user.update"

	// EventUserDelete records a user record being removed.
	EventUserDelete EventType = "user.delete"

	// EventUserRead records a user record being read.
	EventUserRead EventType = "user.read"
)

// EventResult represents the outcome of an audit event.
type EventResult string

const (
	// EventResultSuccess indicates the operation succeeded.
	EventResultSuccess EventResult = "success"

	// EventResultFailure indicates the operation failed.
	EventResultFailure EventResult = "failure"

	// EventResultDenied indicates the operation was denied (authorization failure).
	EventResultDenied EventResult = "denied"
)

// AuditEvent represents a security-relevant event that should be logged.
// Fields follow industry best practices for audit logging (NIST, OWASP, CIS).
//
// The name stutters, but renaming an exported type breaks every downstream
// caller, so it stands until v2 renames it to Event.
//
//nolint:revive // Renaming an exported type is a breaking change; deferred to v2.
type AuditEvent struct {
	// Timestamp is when the event occurred (UTC, RFC3339 format recommended).
	Timestamp time.Time `json:"timestamp"`

	// EventType identifies the type of event (e.g., "auth.login").
	EventType EventType `json:"event_type"`

	// EventResult indicates whether the event succeeded or failed.
	EventResult EventResult `json:"event_result"`

	// Actor identifies who performed the action.
	Actor *Actor `json:"actor,omitempty"`

	// Resource identifies what was accessed or modified.
	Resource *Resource `json:"resource,omitempty"`

	// Source contains information about where the request originated.
	Source *Source `json:"source,omitempty"`

	// Error contains error details if the event failed.
	Error string `json:"error,omitempty"`

	// Metadata contains additional event-specific data.
	// Use this for extensibility while maintaining a consistent base schema.
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	// SessionID tracks the session associated with this event.
	SessionID string `json:"session_id,omitempty"`

	// TraceID enables correlation across distributed systems (optional).
	TraceID string `json:"trace_id,omitempty"`
}

// Actor represents the entity performing an action.
type Actor struct {
	// UserID is the unique identifier for the user.
	UserID string `json:"user_id,omitempty"`

	// Email is the user's email address (may be redacted based on configuration).
	Email string `json:"email,omitempty"`

	// Username is the user's username (may be redacted).
	Username string `json:"username,omitempty"`

	// Provider identifies the authentication provider (e.g., "google", "github", "basic").
	Provider string `json:"provider,omitempty"`

	// Roles contains the user's roles or permissions at the time of the event.
	Roles []string `json:"roles,omitempty"`
}

// Resource represents the target of an action.
type Resource struct {
	// Type identifies the resource type (e.g., "user", "token", "session").
	Type string `json:"type"`

	// ID is the unique identifier for the resource.
	ID string `json:"id,omitempty"`

	// Name is a human-readable name for the resource.
	Name string `json:"name,omitempty"`

	// Attributes contains additional resource metadata.
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

// Source represents the origin of a request.
type Source struct {
	// IPAddress is the client's IP address.
	IPAddress string `json:"ip_address,omitempty"`

	// UserAgent is the client's user agent string.
	UserAgent string `json:"user_agent,omitempty"`

	// Location contains geographic information (optional).
	Location string `json:"location,omitempty"`

	// DeviceID identifies the device (optional).
	DeviceID string `json:"device_id,omitempty"`

	// RequestID tracks the HTTP request (for correlation).
	RequestID string `json:"request_id,omitempty"`
}

// RedactionConfig controls PII redaction in audit logs.
// This enables compliance with privacy regulations (GDPR, CCPA, etc.).
type RedactionConfig struct {
	// RedactEmail controls whether email addresses are redacted.
	// When true, emails are masked (e.g., "u***@example.com").
	RedactEmail bool

	// RedactUsername controls whether usernames are redacted.
	RedactUsername bool

	// RedactIPAddress controls whether IP addresses are redacted.
	// When true, IPs are masked (e.g., "192.168.1.***").
	RedactIPAddress bool

	// RedactMetadata controls whether metadata fields are redacted.
	// When true, specified metadata keys are removed or masked.
	RedactMetadata bool

	// MetadataRedactionKeys specifies which metadata keys to redact.
	MetadataRedactionKeys []string

	// CustomRedactor allows custom redaction logic.
	// If provided, this function is called before logging.
	CustomRedactor func(*AuditEvent) *AuditEvent
}

// ApplyRedaction applies the configured redaction rules to an event.
func (rc *RedactionConfig) ApplyRedaction(event *AuditEvent) *AuditEvent {
	if rc == nil {
		return event
	}

	// Create a copy to avoid modifying the original
	redacted := *event

	// Apply custom redactor first if provided
	if rc.CustomRedactor != nil {
		return rc.CustomRedactor(&redacted)
	}

	// Redact actor information
	if redacted.Actor != nil {
		actor := *redacted.Actor
		if rc.RedactEmail && actor.Email != "" {
			actor.Email = redactEmail(actor.Email)
		}
		if rc.RedactUsername && actor.Username != "" {
			actor.Username = redactString(actor.Username)
		}
		redacted.Actor = &actor
	}

	// Redact source information
	if redacted.Source != nil {
		source := *redacted.Source
		if rc.RedactIPAddress && source.IPAddress != "" {
			source.IPAddress = redactIPAddress(source.IPAddress)
		}
		redacted.Source = &source
	}

	// Redact metadata
	if rc.RedactMetadata && redacted.Metadata != nil {
		metadata := make(map[string]interface{})
		for k, v := range redacted.Metadata {
			if contains(rc.MetadataRedactionKeys, k) {
				metadata[k] = "[REDACTED]"
			} else {
				metadata[k] = v
			}
		}
		redacted.Metadata = metadata
	}

	return &redacted
}

// redactEmail masks an email address (e.g., "user@example.com" -> "u***@example.com").
func redactEmail(email string) string {
	if len(email) < 2 {
		return "***"
	}
	// Find @ symbol
	atIndex := -1
	for i, c := range email {
		if c == '@' {
			atIndex = i
			break
		}
	}
	if atIndex <= 0 {
		return "***"
	}
	return string(email[0]) + "***@" + email[atIndex+1:]
}

// redactString masks a string (e.g., "username" -> "u***e").
func redactString(s string) string {
	if len(s) < 2 {
		return "***"
	}
	if len(s) == 2 {
		return string(s[0]) + "*"
	}
	return string(s[0]) + "***" + string(s[len(s)-1])
}

// redactIPAddress masks an IP address (e.g., "192.168.1.1" -> "192.168.*.*").
func redactIPAddress(ip string) string {
	// Simple IPv4 redaction
	count := 0
	lastDot := -1
	for i, c := range ip {
		if c == '.' {
			count++
			if count == 2 {
				lastDot = i
				break
			}
		}
	}
	if lastDot > 0 {
		return ip[:lastDot] + ".*.*"
	}
	// For IPv6 or malformed, just mask everything after first segment
	for i, c := range ip {
		if c == ':' || c == '.' {
			return ip[:i] + ":***"
		}
	}
	return "***"
}

// contains checks if a string slice contains a value.
func contains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
