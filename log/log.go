// Package log provides a minimal logging interface for the IPFAR SDK.
//
// It allows users to inject their own logger implementation (e.g., zerolog, zap,
// logrus) or rely on the built-in DefaultLogger that writes to stderr.
//
// Usage:
//
//	// Use the default logger (stderr, Info level)
//	log.Info(ctx, "uploading CAR for %s", rootCID)
//
//	// Inject a custom logger
//	log.SetGlobalLogger(myZerologAdapter)
package log

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Level represents log severity.
type Level int

const (
	DebugLevel Level = iota
	InfoLevel
	WarnLevel
	ErrorLevel
)

func (l Level) String() string {
	switch l {
	case DebugLevel:
		return "DEBUG"
	case InfoLevel:
		return "INFO"
	case WarnLevel:
		return "WARN"
	case ErrorLevel:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// Logger is the interface for SDK logging.
// Implementations can wrap any logging library.
type Logger interface {
	Debug(ctx context.Context, msg string, args ...interface{})
	Info(ctx context.Context, msg string, args ...interface{})
	Warn(ctx context.Context, msg string, args ...interface{})
	Error(ctx context.Context, msg string, args ...interface{})
}

// ── Global logger ────────────────────────────────────────────────────────

var (
	globalLogger Logger = NewDefaultLogger(InfoLevel)
	mu           sync.RWMutex
)

// SetGlobalLogger sets the global logger instance used by the SDK.
func SetGlobalLogger(logger Logger) {
	mu.Lock()
	defer mu.Unlock()
	if logger != nil {
		globalLogger = logger
	}
}

// L returns the global logger instance.
func L() Logger {
	mu.RLock()
	defer mu.RUnlock()
	return globalLogger
}

// Convenience functions that delegate to the global logger.

// Debug logs a message at Debug level.
func Debug(ctx context.Context, msg string, args ...interface{}) {
	L().Debug(ctx, msg, args...)
}

// Info logs a message at Info level.
func Info(ctx context.Context, msg string, args ...interface{}) {
	L().Info(ctx, msg, args...)
}

// Warn logs a message at Warn level.
func Warn(ctx context.Context, msg string, args ...interface{}) {
	L().Warn(ctx, msg, args...)
}

// Error logs a message at Error level.
func Error(ctx context.Context, msg string, args ...interface{}) {
	L().Error(ctx, msg, args...)
}

// ── DefaultLogger ─────────────────────────────────────────────────────────

// DefaultLogger writes to stderr with a simple text format.
// This is what the SDK uses by default.
type DefaultLogger struct {
	Level Level
	w     io.Writer
}

// NewDefaultLogger creates a new DefaultLogger that writes to stderr.
func NewDefaultLogger(level Level) *DefaultLogger {
	return &DefaultLogger{
		Level: level,
		w:     os.Stderr,
	}
}

func (l *DefaultLogger) log(level Level, ctx context.Context, msg string, args ...interface{}) {
	if level < l.Level {
		return
	}
	ts := time.Now().Format("2006-01-02T15:04:05.000")
	formatted := msg
	if len(args) > 0 {
		formatted = fmt.Sprintf(msg, args...)
	}
	fmt.Fprintf(l.w, "%s %-5s %s\n", ts, level.String(), formatted)
}

// Debug logs at Debug level.
func (l *DefaultLogger) Debug(ctx context.Context, msg string, args ...interface{}) {
	l.log(DebugLevel, ctx, msg, args...)
}

// Info logs at Info level.
func (l *DefaultLogger) Info(ctx context.Context, msg string, args ...interface{}) {
	l.log(InfoLevel, ctx, msg, args...)
}

// Warn logs at Warn level.
func (l *DefaultLogger) Warn(ctx context.Context, msg string, args ...interface{}) {
	l.log(WarnLevel, ctx, msg, args...)
}

// Error logs at Error level.
func (l *DefaultLogger) Error(ctx context.Context, msg string, args ...interface{}) {
	l.log(ErrorLevel, ctx, msg, args...)
}

// Ensure DefaultLogger implements Logger.
var _ Logger = (*DefaultLogger)(nil)
