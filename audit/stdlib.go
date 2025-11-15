package audit

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
)

// StdLogger implements AuditLogger using the standard library log package.
// It outputs structured JSON logs suitable for ingestion by log aggregation systems.
type StdLogger struct {
	logger          *log.Logger
	redactionConfig *RedactionConfig
}

// StdLoggerConfig configures the standard library logger.
type StdLoggerConfig struct {
	// Logger is the underlying log.Logger to use.
	// If nil, a new logger writing to os.Stderr will be created.
	Logger *log.Logger

	// Output is the writer to send logs to (e.g., os.Stdout, os.Stderr, file).
	// If both Logger and Output are nil, defaults to os.Stderr.
	Output io.Writer

	// RedactionConfig controls PII redaction in logs.
	// If nil, no redaction is applied.
	RedactionConfig *RedactionConfig

	// Prefix is added to each log line (optional).
	Prefix string

	// Flags are log.Logger flags (defaults to log.LstdFlags if 0).
	Flags int
}

// NewStdLogger creates a new standard library audit logger.
func NewStdLogger(cfg StdLoggerConfig) *StdLogger {
	var logger *log.Logger

	if cfg.Logger != nil {
		logger = cfg.Logger
	} else {
		output := cfg.Output
		if output == nil {
			output = os.Stderr
		}

		flags := cfg.Flags
		if flags == 0 {
			flags = log.LstdFlags | log.LUTC
		}

		logger = log.New(output, cfg.Prefix, flags)
	}

	return &StdLogger{
		logger:          logger,
		redactionConfig: cfg.RedactionConfig,
	}
}

// Log records an audit event as a structured JSON log entry.
func (s *StdLogger) Log(ctx context.Context, event *AuditEvent) error {
	if event == nil {
		return nil
	}

	// Apply redaction if configured
	logEvent := event
	if s.redactionConfig != nil {
		logEvent = s.redactionConfig.ApplyRedaction(event)
	}

	// Marshal to JSON
	data, err := json.Marshal(logEvent)
	if err != nil {
		// Log the error but don't fail the operation
		s.logger.Printf("ERROR: failed to marshal audit event: %v", err)
		return err
	}

	// Write to log
	s.logger.Println(string(data))
	return nil
}

// SetRedactionConfig updates the redaction configuration.
func (s *StdLogger) SetRedactionConfig(config *RedactionConfig) {
	s.redactionConfig = config
}

// DefaultStdLogger creates a standard logger with sensible defaults:
// - Logs to stderr
// - UTC timestamps
// - No PII redaction (configure explicitly for production)
func DefaultStdLogger() *StdLogger {
	return NewStdLogger(StdLoggerConfig{
		Output: os.Stderr,
		Flags:  log.LstdFlags | log.LUTC,
	})
}

// ProductionStdLogger creates a standard logger with production-safe defaults:
// - Logs to stdout (for container environments)
// - UTC timestamps
// - PII redaction enabled for email, username, and IP addresses
func ProductionStdLogger() *StdLogger {
	return NewStdLogger(StdLoggerConfig{
		Output: os.Stdout,
		Flags:  log.LstdFlags | log.LUTC,
		RedactionConfig: &RedactionConfig{
			RedactEmail:     true,
			RedactUsername:  true,
			RedactIPAddress: true,
			RedactMetadata:  false, // Customize based on your metadata usage
		},
	})
}
