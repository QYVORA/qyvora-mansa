// Package errors defines typed process-exit errors used by the CLI and console
// to map failures to the correct exit code.
package errors

import (
	"fmt"
	"os"
)

// ExitError carries a process exit code and optional cause.
type ExitError struct {
	Code    int
	Message string
	Cause   error
}

// NewExitError creates a new typed exit error.
func NewExitError(code int, msg string) *ExitError {
	return &ExitError{Code: code, Message: msg}
}

// WrapExitError wraps a cause into a typed exit error.
func WrapExitError(code int, msg string, cause error) *ExitError {
	return &ExitError{Code: code, Message: msg, Cause: cause}
}

func (e *ExitError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

func (e *ExitError) Unwrap() error { return e.Cause }

// Fatal prints to stderr and calls os.Exit.
func Fatal(code int, format string, args ...any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(code)
}
