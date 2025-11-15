package audit

import (
	"testing"
	"time"
)

func TestRedactionConfig_ApplyRedaction(t *testing.T) {
	tests := []struct {
		name   string
		config *RedactionConfig
		event  *AuditEvent
		want   func(*AuditEvent) bool
	}{
		{
			name:   "nil config does nothing",
			config: nil,
			event: &AuditEvent{
				Actor: &Actor{
					Email:    "test@example.com",
					Username: "testuser",
				},
				Source: &Source{
					IPAddress: "192.168.1.1",
				},
			},
			want: func(e *AuditEvent) bool {
				return e.Actor.Email == "test@example.com" &&
					e.Actor.Username == "testuser" &&
					e.Source.IPAddress == "192.168.1.1"
			},
		},
		{
			name: "redact email",
			config: &RedactionConfig{
				RedactEmail: true,
			},
			event: &AuditEvent{
				Actor: &Actor{
					Email: "test@example.com",
				},
			},
			want: func(e *AuditEvent) bool {
				return e.Actor.Email == "t***@example.com"
			},
		},
		{
			name: "redact username",
			config: &RedactionConfig{
				RedactUsername: true,
			},
			event: &AuditEvent{
				Actor: &Actor{
					Username: "testuser",
				},
			},
			want: func(e *AuditEvent) bool {
				return e.Actor.Username == "t***r"
			},
		},
		{
			name: "redact IP address",
			config: &RedactionConfig{
				RedactIPAddress: true,
			},
			event: &AuditEvent{
				Source: &Source{
					IPAddress: "192.168.1.1",
				},
			},
			want: func(e *AuditEvent) bool {
				return e.Source.IPAddress == "192.168.*.*"
			},
		},
		{
			name: "redact metadata",
			config: &RedactionConfig{
				RedactMetadata:        true,
				MetadataRedactionKeys: []string{"password", "secret"},
			},
			event: &AuditEvent{
				Metadata: map[string]interface{}{
					"password": "secret123",
					"secret":   "topsecret",
					"public":   "visible",
				},
			},
			want: func(e *AuditEvent) bool {
				return e.Metadata["password"] == "[REDACTED]" &&
					e.Metadata["secret"] == "[REDACTED]" &&
					e.Metadata["public"] == "visible"
			},
		},
		{
			name: "custom redactor",
			config: &RedactionConfig{
				CustomRedactor: func(e *AuditEvent) *AuditEvent {
					e.Actor.Email = "CUSTOM_REDACTED"
					return e
				},
			},
			event: &AuditEvent{
				Actor: &Actor{
					Email: "test@example.com",
				},
			},
			want: func(e *AuditEvent) bool {
				return e.Actor.Email == "CUSTOM_REDACTED"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.ApplyRedaction(tt.event)
			if !tt.want(got) {
				t.Errorf("ApplyRedaction() failed validation for %s", tt.name)
			}
		})
	}
}

func TestRedactEmail(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"user@example.com", "u***@example.com"},
		{"a@b.com", "a***@b.com"},
		{"@example.com", "***"},
		{"noemail", "***"},
		{"", "***"},
		{"x", "***"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := redactEmail(tt.input)
			if got != tt.want {
				t.Errorf("redactEmail(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRedactString(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"username", "u***e"},
		{"user", "u***r"},
		{"ab", "a*"},
		{"a", "***"},
		{"", "***"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := redactString(tt.input)
			if got != tt.want {
				t.Errorf("redactString(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRedactIPAddress(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"192.168.1.1", "192.168.*.*"},
		{"10.0.0.1", "10.0.*.*"},
		{"2001:0db8:85a3::8a2e:0370:7334", "2001:***"},
		{"192.168", "192:***"},
		{"invalid", "***"},
		{"", "***"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := redactIPAddress(tt.input)
			if got != tt.want {
				t.Errorf("redactIPAddress(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestEventTypeConstants(t *testing.T) {
	// Ensure event type constants are defined correctly
	eventTypes := []EventType{
		EventAuthLogin,
		EventAuthLogout,
		EventAuthRegister,
		EventAuthPasswordChange,
		EventAuthPasswordReset,
		EventTokenGenerate,
		EventTokenValidate,
		EventTokenRefresh,
		EventTokenRevoke,
		EventSessionCreate,
		EventSessionValidate,
		EventSessionRefresh,
		EventSessionDelete,
		EventWebAuthnRegisterBegin,
		EventWebAuthnRegisterFinish,
		EventWebAuthnLoginBegin,
		EventWebAuthnLoginFinish,
		EventOIDCAuthorize,
		EventOIDCCallback,
		EventOIDCExchange,
		EventUserCreate,
		EventUserUpdate,
		EventUserDelete,
		EventUserRead,
	}

	// Ensure all event types are non-empty strings
	for _, et := range eventTypes {
		if et == "" {
			t.Errorf("Event type constant is empty")
		}
	}
}

func TestEventResultConstants(t *testing.T) {
	results := []EventResult{
		EventResultSuccess,
		EventResultFailure,
		EventResultDenied,
	}

	for _, r := range results {
		if r == "" {
			t.Errorf("Event result constant is empty")
		}
	}
}

func TestAuditEvent_Structure(t *testing.T) {
	// Test that AuditEvent can be created with all fields
	now := time.Now()
	event := &AuditEvent{
		Timestamp:   now,
		EventType:   EventAuthLogin,
		EventResult: EventResultSuccess,
		Actor: &Actor{
			UserID:   "user123",
			Email:    "user@example.com",
			Username: "testuser",
			Provider: "basic",
			Roles:    []string{"admin", "user"},
		},
		Resource: &Resource{
			Type: "user",
			ID:   "user123",
			Name: "Test User",
			Attributes: map[string]interface{}{
				"key": "value",
			},
		},
		Source: &Source{
			IPAddress: "192.168.1.1",
			UserAgent: "Mozilla/5.0",
			Location:  "US",
			DeviceID:  "device123",
			RequestID: "req123",
		},
		Error:     "some error",
		Metadata:  map[string]interface{}{"key": "value"},
		SessionID: "session123",
		TraceID:   "trace123",
	}

	// Basic validation
	if event.Timestamp != now {
		t.Errorf("Timestamp mismatch")
	}
	if event.EventType != EventAuthLogin {
		t.Errorf("EventType mismatch")
	}
	if event.Actor.UserID != "user123" {
		t.Errorf("Actor.UserID mismatch")
	}
	if event.Resource.Type != "user" {
		t.Errorf("Resource.Type mismatch")
	}
	if event.Source.IPAddress != "192.168.1.1" {
		t.Errorf("Source.IPAddress mismatch")
	}
}
