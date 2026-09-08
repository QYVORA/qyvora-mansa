// Package table renders aligned terminal tables without box borders.
package table

import (
	"fmt"
	"io"
	"strings"
)

const (
	DefaultWidth   = 100
	MinTableWidth  = 40
	suffixTruncate = "…"
)

// Table is a simple column-aligned table.
type Table struct {
	headers []string
	rows    [][]string
	width   int
}

// New creates a table with the given headers.
func New(headers ...string) *Table {
	return &Table{headers: headers}
}

// SetWidth sets the maximum table width.
func (t *Table) SetWidth(w int) *Table { t.width = w; return t }

// AddRow appends a data row.
func (t *Table) AddRow(cells ...string) {
	row := make([]string, len(t.headers))
	for i := range row {
		if i < len(cells) {
			row[i] = cells[i]
		}
	}
	t.rows = append(t.rows, row)
}

// Empty reports whether the table has no data rows.
func (t *Table) Empty() bool { return len(t.rows) == 0 }

// Len returns the number of data rows.
func (t *Table) Len() int { return len(t.rows) }

// Render writes the table to w.
func (t *Table) Render(w io.Writer) {
	if len(t.headers) == 0 {
		return
	}
	widths := t.computeWidths()
	for i, h := range t.headers {
		fmt.Fprintf(w, "%-*s  ", widths[i], strings.ToUpper(h))
	}
	fmt.Fprintln(w)
	for _, row := range t.rows {
		for i, cell := range row {
			if i < len(widths) {
				fmt.Fprintf(w, "%-*s  ", widths[i], truncate(cell, widths[i]))
			}
		}
		fmt.Fprintln(w)
	}
}

// String returns the table as a string.
func (t *Table) String() string {
	var b strings.Builder
	t.Render(&b)
	return b.String()
}

func (t *Table) computeWidths() []int {
	w := t.width
	if w <= 0 {
		w = DefaultWidth
	}
	n := len(t.headers)
	widths := make([]int, n)
	for i, h := range t.headers {
		widths[i] = len(h)
	}
	for _, row := range t.rows {
		for i, cell := range row {
			if i < n && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}
	gaps := n - 1
	budget := w - gaps*2
	total := 0
	for _, ww := range widths {
		total += ww
	}
	if total <= budget {
		return widths
	}
	for total > budget {
		maxI := 0
		for i := 1; i < n; i++ {
			if widths[i] > widths[maxI] {
				maxI = i
			}
		}
		widths[maxI]--
		total--
		if widths[maxI] < MinTableWidth/n {
			break
		}
	}
	return widths
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 1 {
		return s[:max]
	}
	return s[:max-1] + suffixTruncate
}
