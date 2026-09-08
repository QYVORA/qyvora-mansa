package console

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	historyLimit    = 1000
	historyFileName = ".mansa_history"
)

// History is an in-memory command history.
type History struct {
	lines []string
}

// NewHistory returns an empty history.
func NewHistory() *History { return &History{} }

// Add records a line, deduplicating consecutive repeats and capping size.
func (h *History) Add(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	if n := len(h.lines); n > 0 && h.lines[n-1] == line {
		return
	}
	h.lines = append(h.lines, line)
	if len(h.lines) > historyLimit {
		h.lines = h.lines[len(h.lines)-historyLimit:]
	}
}

// Lines returns a copy of the history lines.
func (h *History) Lines() []string {
	out := make([]string, len(h.lines))
	copy(out, h.lines)
	return out
}

// Len returns the number of history lines.
func (h *History) Len() int { return len(h.lines) }

// historyPath returns the persistent history file path.
func historyPath() (string, bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", false
	}
	return filepath.Join(home, historyFileName), true
}
