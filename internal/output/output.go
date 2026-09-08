// Package output provides formatted output for Mansa. It supports terminal
// (human), json, yaml, markdown, and html output modes. Terminal output
// goes to stdout; the printer is never used for log output (which goes
// through the logger to stderr).
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"go.yaml.in/yaml/v3"
)

// Format represents an output format.
type Format string

const (
	FormatTerminal Format = "terminal"
	FormatJSON     Format = "json"
	FormatYAML     Format = "yaml"
	FormatMarkdown Format = "markdown"
	FormatHTML     Format = "html"
)

// ParseFormat normalizes a format string.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "terminal", "table", "text":
		return FormatTerminal, nil
	case "json":
		return FormatJSON, nil
	case "yaml":
		return FormatYAML, nil
	case "markdown", "md":
		return FormatMarkdown, nil
	case "html":
		return FormatHTML, nil
	default:
		return "", fmt.Errorf("unknown output format %q (supported: terminal, json, yaml, markdown, html)", s)
	}
}

// Printer handles formatted output.
type Printer struct {
	mu     sync.Mutex
	w      io.Writer
	format Format
}

// New returns a terminal-mode printer writing to stdout.
func New() *Printer {
	return &Printer{w: os.Stdout, format: FormatTerminal}
}

// SetFormat changes the output format.
func (p *Printer) SetFormat(f Format) { p.mu.Lock(); p.format = f; p.mu.Unlock() }

// Format returns the current format.
func (p *Printer) Format() Format { p.mu.Lock(); defer p.mu.Unlock(); return p.format }

// Writer returns the underlying writer.
func (p *Printer) Writer() io.Writer { return p.w }

// Print writes v in the configured format.
func (p *Printer) Print(v any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch p.format {
	case FormatJSON:
		enc := json.NewEncoder(p.w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(v)
	case FormatYAML:
		b, err := json.Marshal(v)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
		var raw any
		if err := yaml.Unmarshal(b, &raw); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
		enc := yaml.NewEncoder(p.w)
		enc.SetIndent(2)
		_ = enc.Encode(raw)
	case FormatMarkdown:
		b, _ := json.MarshalIndent(v, "", "  ")
		fmt.Fprintf(p.w, "```json\n%s\n```\n", string(b))
	case FormatHTML:
		b, _ := json.MarshalIndent(v, "", "  ")
		fmt.Fprintf(p.w, "<pre>\n%s\n</pre>\n", string(b))
	default:
		fmt.Fprintf(p.w, "%v\n", v)
	}
}

// PrintTable renders a simple aligned table in terminal format.
func (p *Printer) PrintTable(headers []string, rows [][]string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.format == FormatJSON || p.format == FormatYAML {
		out := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			m := make(map[string]any, len(headers))
			for i, h := range headers {
				if i < len(row) {
					m[h] = row[i]
				}
			}
			out = append(out, m)
		}
		p.Print(out)
		return
	}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}
	for i, h := range headers {
		fmt.Fprintf(p.w, "%-*s  ", widths[i], strings.ToUpper(h))
	}
	fmt.Fprintln(p.w)
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) {
				fmt.Fprintf(p.w, "%-*s  ", widths[i], cell)
			}
		}
		fmt.Fprintln(p.w)
	}
}
