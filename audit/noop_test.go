package audit

import (
	"context"
	"testing"
	"time"
)

func TestNoOpAuditor_Log(t *testing.T) {
	auditor := NewNoOpAuditor()

	event := &AuditEvent{
		Timestamp:   time.Now(),
		EventType:   EventAuthLogin,
		EventResult: EventResultSuccess,
	}

	// Should not return error
	err := auditor.Log(context.Background(), event)
	if err != nil {
		t.Errorf("NoOpAuditor.Log() returned error: %v", err)
	}
}

func TestNoOpAuditor_LogNil(t *testing.T) {
	auditor := NewNoOpAuditor()

	// Should not panic with nil event
	err := auditor.Log(context.Background(), nil)
	if err != nil {
		t.Errorf("NoOpAuditor.Log() with nil event returned error: %v", err)
	}
}

func TestDefaultAuditor(t *testing.T) {
	auditor := DefaultAuditor()
	if auditor == nil {
		t.Errorf("DefaultAuditor() returned nil")
	}

	// Should be able to log
	err := auditor.Log(context.Background(), &AuditEvent{
		Timestamp:   time.Now(),
		EventType:   EventAuthLogin,
		EventResult: EventResultSuccess,
	})
	if err != nil {
		t.Errorf("DefaultAuditor().Log() returned error: %v", err)
	}
}

func BenchmarkNoOpAuditor_Log(b *testing.B) {
	auditor := NewNoOpAuditor()
	event := &AuditEvent{
		Timestamp:   time.Now(),
		EventType:   EventAuthLogin,
		EventResult: EventResultSuccess,
		Actor: &Actor{
			UserID: "user123",
			Email:  "user@example.com",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = auditor.Log(context.Background(), event)
	}
}
