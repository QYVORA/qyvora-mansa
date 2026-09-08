// Package logger provides a structured stderr logger for Mansa.
// Logs go to stderr; user output goes to stdout; events go to the event stream.
package logger

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// Level represents the current logging level.
type Level int

const (
	LevelSilent Level = iota
	LevelError
	LevelWarn
	LevelInfo
	LevelDebug
)

// ParseLevel converts a string to a Level (case-insensitive).
func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn":
		return LevelWarn
	case "error":
		return LevelError
	case "silent":
		return LevelSilent
	default:
		return LevelInfo
	}
}

// Logger writes structured log lines to stderr.
type Logger struct {
	mu      sync.Mutex
	w       io.Writer
	level   Level
	verbose bool
	quiet   bool
}

// New returns a logger writing to stderr at Info level.
func New() *Logger {
	return &Logger{w: os.Stderr, level: LevelInfo}
}

func (l *Logger) SetWriter(w io.Writer) { l.mu.Lock(); l.w = w; l.mu.Unlock() }
func (l *Logger) SetLevel(lv Level)     { l.mu.Lock(); l.level = lv; l.mu.Unlock() }
func (l *Logger) SetVerbose(v bool)     { l.mu.Lock(); l.verbose = v; l.mu.Unlock() }
func (l *Logger) SetQuiet(q bool)       { l.mu.Lock(); l.quiet = q; l.mu.Unlock() }

func (l *Logger) Errorf(format string, args ...any) { l.logf(LevelError, "ERROR", format, args...) }
func (l *Logger) Warnf(format string, args ...any)  { l.logf(LevelWarn, "WARN", format, args...) }
func (l *Logger) Infof(format string, args ...any)  { l.logf(LevelInfo, "INFO", format, args...) }
func (l *Logger) Debugf(format string, args ...any) { l.logf(LevelDebug, "DEBUG", format, args...) }

func (l *Logger) logf(level Level, label, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if level > l.level {
		return
	}
	if l.quiet && level < LevelWarn && !l.verbose {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(l.w, "[mansa][%s] %s\n", label, msg)
}
