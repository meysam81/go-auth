package audit

import "context"

// NoOpAuditor is a no-op implementation of AuditLogger that does nothing.
// This is the default auditor and is useful when audit logging is not required
// or disabled in development environments.
//
// It is also the default an audit wrapper falls back to when it is constructed
// with a nil AuditLogger, which means a deployment that forgets to configure a
// sink produces no audit trail and no error. That is the intended zero-overhead
// behavior for development; a deployment relying on the trail as compliance
// evidence must pass a real AuditLogger explicitly.
type NoOpAuditor struct{}

// NewNoOpAuditor creates a new no-op auditor.
func NewNoOpAuditor() *NoOpAuditor {
	return &NoOpAuditor{}
}

// Log does nothing and always returns nil.
func (n *NoOpAuditor) Log(ctx context.Context, event *AuditEvent) error {
	return nil
}

// DefaultAuditor returns a no-op auditor as the default implementation.
// This ensures the library has safe, zero-overhead defaults.
func DefaultAuditor() AuditLogger {
	return NewNoOpAuditor()
}
