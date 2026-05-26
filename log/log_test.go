package log

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
)

// newTestLogger creates a DefaultLogger that writes to a buffer.
func newTestLogger(level Level) (*DefaultLogger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	l := &DefaultLogger{
		Level: level,
		w:     buf,
	}
	return l, buf
}

func TestDefaultLogger_OutputLevels(t *testing.T) {
	l, buf := newTestLogger(DebugLevel)
	ctx := context.Background()

	l.Debug(ctx, "debug msg")
	l.Info(ctx, "info msg")
	l.Warn(ctx, "warn msg")
	l.Error(ctx, "error msg")

	out := buf.String()

	// %-5s pads short level names: "INFO " -> "INFO  " (double space before msg)
	if !strings.Contains(out, "DEBUG debug msg") {
		t.Errorf("expected DEBUG output, got: %s", out)
	}
	if !strings.Contains(out, "INFO  info msg") {
		t.Errorf("expected INFO output, got: %s", out)
	}
	if !strings.Contains(out, "WARN  warn msg") {
		t.Errorf("expected WARN output, got: %s", out)
	}
	if !strings.Contains(out, "ERROR error msg") {
		t.Errorf("expected ERROR output, got: %s", out)
	}
}

func TestDefaultLogger_LevelFiltering(t *testing.T) {
	l, buf := newTestLogger(InfoLevel)
	ctx := context.Background()

	l.Debug(ctx, "should not appear")
	l.Info(ctx, "should appear")
	l.Warn(ctx, "should also appear")
	l.Error(ctx, "should appear too")

	out := buf.String()

	if strings.Contains(out, "DEBUG") {
		t.Errorf("DEBUG should be filtered at InfoLevel, got: %s", out)
	}
	if !strings.Contains(out, "INFO") {
		t.Errorf("INFO should appear at InfoLevel, got: %s", out)
	}
	if !strings.Contains(out, "WARN") {
		t.Errorf("WARN should appear at InfoLevel, got: %s", out)
	}
	if !strings.Contains(out, "ERROR") {
		t.Errorf("ERROR should appear at InfoLevel, got: %s", out)
	}
}

func TestDefaultLogger_FormatArgs(t *testing.T) {
	l, buf := newTestLogger(DebugLevel)
	ctx := context.Background()

	l.Info(ctx, "value=%d name=%s", 42, "test")

	out := buf.String()
	if !strings.Contains(out, "value=42 name=test") {
		t.Errorf("expected formatted output, got: %s", out)
	}
}

func TestDefaultLogger_WarnLevelFiltersDebugInfo(t *testing.T) {
	l, buf := newTestLogger(WarnLevel)
	ctx := context.Background()

	l.Debug(ctx, "debug")
	l.Info(ctx, "info")
	l.Warn(ctx, "warn")
	l.Error(ctx, "error")

	out := buf.String()

	if strings.Contains(out, "DEBUG") || strings.Contains(out, "INFO") {
		t.Errorf("DEBUG and INFO should be filtered at WarnLevel, got: %s", out)
	}
	if !strings.Contains(out, "WARN") || !strings.Contains(out, "ERROR") {
		t.Errorf("WARN and ERROR should appear at WarnLevel, got: %s", out)
	}
}

func TestDefaultLogger_ErrorLevelOnly(t *testing.T) {
	l, buf := newTestLogger(ErrorLevel)
	ctx := context.Background()

	l.Debug(ctx, "debug")
	l.Info(ctx, "info")
	l.Warn(ctx, "warn")
	l.Error(ctx, "error")

	out := buf.String()

	// Only ERROR should appear.
	if strings.Contains(out, "DEBUG") || strings.Contains(out, "INFO") || strings.Contains(out, "WARN") {
		t.Errorf("only ERROR should appear at ErrorLevel, got: %s", out)
	}
	if !strings.Contains(out, "ERROR") {
		t.Errorf("ERROR should appear at ErrorLevel, got: %s", out)
	}
}

func TestSetGlobalLogger(t *testing.T) {
	// Save original and restore after test.
	original := globalLogger
	defer func() { globalLogger = original }()

	l, _ := newTestLogger(DebugLevel)
	SetGlobalLogger(l)

	got := L()
	if got != l {
		t.Errorf("L() returned %v, want %v", got, l)
	}
}

func TestSetGlobalLogger_Nil(t *testing.T) {
	original := globalLogger
	defer func() { globalLogger = original }()

	SetGlobalLogger(nil)
	// Should not change the global logger.
	if globalLogger != original {
		t.Error("SetGlobalLogger(nil) should not change global logger")
	}
}

func TestConvenienceFunctions(t *testing.T) {
	original := globalLogger
	defer func() { globalLogger = original }()

	l, buf := newTestLogger(DebugLevel)
	SetGlobalLogger(l)
	ctx := context.Background()

	Debug(ctx, "debug via convenience")
	Info(ctx, "info via convenience")
	Warn(ctx, "warn via convenience")
	Error(ctx, "error via convenience")

	out := buf.String()

	if !strings.Contains(out, "DEBUG debug via convenience") {
		t.Errorf("Debug convenience function failed, got: %s", out)
	}
	if !strings.Contains(out, "INFO  info via convenience") {
		t.Errorf("Info convenience function failed, got: %s", out)
	}
	if !strings.Contains(out, "WARN  warn via convenience") {
		t.Errorf("Warn convenience function failed, got: %s", out)
	}
	if !strings.Contains(out, "ERROR error via convenience") {
		t.Errorf("Error convenience function failed, got: %s", out)
	}
}

func TestConcurrency(t *testing.T) {
	original := globalLogger
	defer func() { globalLogger = original }()

	l, _ := newTestLogger(DebugLevel)
	SetGlobalLogger(l)
	ctx := context.Background()

	var wg sync.WaitGroup

	// Concurrent writes to the same logger.
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			l.Debug(ctx, "goroutine %d", n)
			l.Info(ctx, "goroutine %d", n)
			l.Warn(ctx, "goroutine %d", n)
			l.Error(ctx, "goroutine %d", n)
		}(i)
	}

	// Concurrent SetGlobalLogger and L() calls.
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			SetGlobalLogger(l)
			_ = L()
		}()
	}

	wg.Wait()
	// If we get here without panicking, the test passes.
}

func TestLevel_String(t *testing.T) {
	tests := []struct {
		level    Level
		expected string
	}{
		{DebugLevel, "DEBUG"},
		{InfoLevel, "INFO"},
		{WarnLevel, "WARN"},
		{ErrorLevel, "ERROR"},
		{Level(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		if got := tt.level.String(); got != tt.expected {
			t.Errorf("Level(%d).String() = %q, want %q", tt.level, got, tt.expected)
		}
	}
}

func TestDefaultLogger_ImplementsLogger(t *testing.T) {
	// Compile-time check, but also verify at runtime.
	var l Logger = NewDefaultLogger(DebugLevel)
	if l == nil {
		t.Error("NewDefaultLogger returned nil")
	}
}
