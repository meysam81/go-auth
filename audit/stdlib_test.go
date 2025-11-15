package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestStdLogger_Log(t *testing.T) {
	var buf bytes.Buffer
	logger := NewStdLogger(StdLoggerConfig{
		Output: &buf,
	})

	event := &AuditEvent{
		Timestamp:   time.Now().UTC(),
		EventType:   EventAuthLogin,
		EventResult: EventResultSuccess,
		Actor: &Actor{
			UserID: "user123",
			Email:  "test@example.com",
		},
	}

	err := logger.Log(context.Background(), event)
	if err != nil {
		t.Fatalf("Log() returned error: %v", err)
	}

	// Check that output is valid JSON
	output := buf.String()
	if output == "" {
		t.Fatal("No output written")
	}

	// Extract JSON part (skip log prefix)
	jsonStart := strings.Index(output, "{")
	if jsonStart == -1 {
		t.Fatalf("No JSON found in output: %s", output)
	}

	// Extract JSON from the start to end, trimming whitespace
	jsonPart := strings.TrimSpace(output[jsonStart:])

	var decoded AuditEvent
	err = json.Unmarshal([]byte(jsonPart), &decoded)
	if err != nil {
		t.Fatalf("Failed to decode JSON output: %v\nOutput: %s", err, output)
	}

	if decoded.EventType != EventAuthLogin {
		t.Errorf("EventType = %v, want %v", decoded.EventType, EventAuthLogin)
	}
	if decoded.Actor.UserID != "user123" {
		t.Errorf("Actor.UserID = %v, want %v", decoded.Actor.UserID, "user123")
	}
}

func TestStdLogger_LogWithRedaction(t *testing.T) {
	var buf bytes.Buffer
	logger := NewStdLogger(StdLoggerConfig{
		Output: &buf,
		RedactionConfig: &RedactionConfig{
			RedactEmail: true,
		},
	})

	event := &AuditEvent{
		Timestamp:   time.Now().UTC(),
		EventType:   EventAuthLogin,
		EventResult: EventResultSuccess,
		Actor: &Actor{
			UserID: "user123",
			Email:  "test@example.com",
		},
	}

	err := logger.Log(context.Background(), event)
	if err != nil {
		t.Fatalf("Log() returned error: %v", err)
	}

	output := buf.String()

	// Should not contain the original email
	if strings.Contains(output, "test@example.com") {
		t.Errorf("Output contains unredacted email: %s", output)
	}

	// Should contain redacted email pattern
	if !strings.Contains(output, "t***@example.com") {
		t.Errorf("Output does not contain redacted email: %s", output)
	}
}

func TestStdLogger_LogNil(t *testing.T) {
	var buf bytes.Buffer
	logger := NewStdLogger(StdLoggerConfig{
		Output: &buf,
	})

	err := logger.Log(context.Background(), nil)
	if err != nil {
		t.Errorf("Log(nil) returned error: %v", err)
	}

	// Should not write anything for nil event
	if buf.Len() > 0 {
		t.Errorf("Log(nil) wrote output: %s", buf.String())
	}
}

func TestStdLogger_SetRedactionConfig(t *testing.T) {
	var buf bytes.Buffer
	logger := NewStdLogger(StdLoggerConfig{
		Output: &buf,
	})

	// Initially no redaction
	event := &AuditEvent{
		Timestamp:   time.Now().UTC(),
		EventType:   EventAuthLogin,
		EventResult: EventResultSuccess,
		Actor: &Actor{
			Email: "test@example.com",
		},
	}

	_ = logger.Log(context.Background(), event)
	output1 := buf.String()
	if !strings.Contains(output1, "test@example.com") {
		t.Errorf("Initial log should contain unredacted email")
	}

	// Enable redaction
	buf.Reset()
	logger.SetRedactionConfig(&RedactionConfig{
		RedactEmail: true,
	})

	_ = logger.Log(context.Background(), event)
	output2 := buf.String()
	if strings.Contains(output2, "test@example.com") {
		t.Errorf("After SetRedactionConfig, log should not contain original email")
	}
	if !strings.Contains(output2, "t***@example.com") {
		t.Errorf("After SetRedactionConfig, log should contain redacted email")
	}
}

func TestDefaultStdLogger(t *testing.T) {
	logger := DefaultStdLogger()
	if logger == nil {
		t.Fatal("DefaultStdLogger() returned nil")
	}

	// Should be able to log without error
	err := logger.Log(context.Background(), &AuditEvent{
		Timestamp:   time.Now(),
		EventType:   EventAuthLogin,
		EventResult: EventResultSuccess,
	})
	if err != nil {
		t.Errorf("DefaultStdLogger().Log() returned error: %v", err)
	}
}

func TestProductionStdLogger(t *testing.T) {
	logger := ProductionStdLogger()
	if logger == nil {
		t.Fatal("ProductionStdLogger() returned nil")
	}

	if logger.redactionConfig == nil {
		t.Error("ProductionStdLogger() should have redaction config")
	}

	if !logger.redactionConfig.RedactEmail {
		t.Error("ProductionStdLogger() should redact emails")
	}

	if !logger.redactionConfig.RedactUsername {
		t.Error("ProductionStdLogger() should redact usernames")
	}

	if !logger.redactionConfig.RedactIPAddress {
		t.Error("ProductionStdLogger() should redact IP addresses")
	}
}

func TestStdLogger_ComplexEvent(t *testing.T) {
	var buf bytes.Buffer
	logger := NewStdLogger(StdLoggerConfig{
		Output: &buf,
	})

	event := &AuditEvent{
		Timestamp:   time.Now().UTC(),
		EventType:   EventAuthLogin,
		EventResult: EventResultSuccess,
		Actor: &Actor{
			UserID:   "user123",
			Email:    "test@example.com",
			Username: "testuser",
			Provider: "basic",
			Roles:    []string{"admin", "user"},
		},
		Resource: &Resource{
			Type: "session",
			ID:   "session123",
			Name: "User Session",
			Attributes: map[string]interface{}{
				"duration": 3600,
			},
		},
		Source: &Source{
			IPAddress: "192.168.1.1",
			UserAgent: "Mozilla/5.0",
			Location:  "US",
			RequestID: "req123",
		},
		SessionID: "session123",
		TraceID:   "trace123",
		Metadata: map[string]interface{}{
			"login_method": "password",
		},
	}

	err := logger.Log(context.Background(), event)
	if err != nil {
		t.Fatalf("Log() returned error: %v", err)
	}

	output := buf.String()
	if output == "" {
		t.Fatal("No output written")
	}

	// Verify all key fields are present in JSON
	requiredFields := []string{
		`"event_type":"auth.login"`,
		`"event_result":"success"`,
		`"user_id":"user123"`,
		`"email":"test@example.com"`,
		`"ip_address":"192.168.1.1"`,
		`"session_id":"session123"`,
		`"trace_id":"trace123"`,
	}

	for _, field := range requiredFields {
		if !strings.Contains(output, field) {
			t.Errorf("Output missing field: %s\nOutput: %s", field, output)
		}
	}
}

func BenchmarkStdLogger_Log(b *testing.B) {
	var buf bytes.Buffer
	logger := NewStdLogger(StdLoggerConfig{
		Output: &buf,
	})

	event := &AuditEvent{
		Timestamp:   time.Now(),
		EventType:   EventAuthLogin,
		EventResult: EventResultSuccess,
		Actor: &Actor{
			UserID: "user123",
			Email:  "test@example.com",
		},
		Source: &Source{
			IPAddress: "192.168.1.1",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = logger.Log(context.Background(), event)
	}
}

func BenchmarkStdLogger_LogWithRedaction(b *testing.B) {
	var buf bytes.Buffer
	logger := NewStdLogger(StdLoggerConfig{
		Output: &buf,
		RedactionConfig: &RedactionConfig{
			RedactEmail:     true,
			RedactIPAddress: true,
		},
	})

	event := &AuditEvent{
		Timestamp:   time.Now(),
		EventType:   EventAuthLogin,
		EventResult: EventResultSuccess,
		Actor: &Actor{
			UserID: "user123",
			Email:  "test@example.com",
		},
		Source: &Source{
			IPAddress: "192.168.1.1",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = logger.Log(context.Background(), event)
	}
}
