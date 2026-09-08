// Package ui provides the shared Mansa terminal UI primitives: banner
// rendering, section headers, HUD, colored text, and aligned output.
// Color is enabled only when the output writer is a TTY and NO_COLOR is
// not set.
package ui

import (
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/QYVORA/qyvora-mansa/internal/banner"
)

const (
	ansiReset = "\x1b[0m"
	ansiBold  = "\x1b[1m"
	ansiDim   = "\x1b[2m"
	ansiCyan  = "\x1b[36m"
	ansiTeal  = "\x1b[38;2;0;186;163m" // brand teal #00BAA3
	ansiDark  = "\x1b[38;2;0;140;120m" // darker teal
	ansiWhite = "\x1b[37m"
	ansiRed   = "\x1b[31m"
	ansiAmber = "\x1b[33m"
)

const consoleSectionWidth = 60

// UI renders terminal UI elements with brand styling.
type UI struct {
	w     io.Writer
	color bool
	width int
}

// NewUI creates a UI bound to w with terminal-aware coloring.
func NewUI(w io.Writer) *UI {
	u := &UI{w: w, width: consoleSectionWidth}
	if os.Getenv("NO_COLOR") == "" {
		if f, ok := w.(*os.File); ok {
			u.color = term.IsTerminal(int(f.Fd()))
		}
	}
	return u
}

func (u *UI) paint(s, code string) string {
	if !u.color || s == "" {
		return s
	}
	return code + s + ansiReset
}

func (u *UI) Teal(s string) string      { return u.paint(s, ansiTeal) }
func (u *UI) BoldTeal(s string) string  { return u.paint(s, ansiBold+ansiTeal) }
func (u *UI) Dark(s string) string      { return u.paint(s, ansiDark) }
func (u *UI) White(s string) string     { return u.paint(s, ansiWhite) }
func (u *UI) BoldWhite(s string) string { return u.paint(s, ansiBold+ansiWhite) }
func (u *UI) DimWhite(s string) string  { return u.paint(s, ansiDim+ansiWhite) }
func (u *UI) Red(s string) string       { return u.paint(s, ansiRed) }
func (u *UI) Amber(s string) string     { return u.paint(s, ansiAmber) }

// Section prints a section header.
func (u *UI) Section(title string) {
	fmt.Fprintln(u.w)
	fmt.Fprintln(u.w, u.BoldTeal("  "+strings.ToUpper(title)))
}

// KV prints a key-value pair with fixed-width label.
func (u *UI) KV(key, value string) {
	fmt.Fprintf(u.w, "%s%s\n", u.DimWhite(padTo(key+":", 22)), u.White(value))
}

// Glyph maps a single-character glyph to its bracketed colored form.
func (u *UI) Glyph(glyph string) string {
	switch glyph {
	case "+":
		return u.Teal("[+] ")
	case "*":
		return u.BoldTeal("[*] ")
	case "!":
		return u.Amber("[!] ")
	case "x", "X":
		return u.Red("[x] ")
	case ">":
		return u.White("[>] ")
	case "v":
		return u.DimWhite("[v] ")
	case "-":
		return u.DimWhite("[-] ")
	default:
		return u.BoldWhite("[" + glyph + "] ")
	}
}

// Status prints a glyph-prefixed status line.
func (u *UI) Status(glyph, format string, args ...any) {
	fmt.Fprintf(u.w, "%s%s\n", u.Glyph(glyph), fmt.Sprintf(format, args...))
}

// Err prints an error to stderr.
func (u *UI) Err(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "%s%s\n", u.Red("[!] "), fmt.Sprintf(format, args...))
}

// Banner renders the canonical Mansa banner with colored glyphs.
func (u *UI) Banner(tagline string) {
	fmt.Fprintln(u.w)
	lines := strings.Split(banner.Art, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" && len(line) > 0 && (line == lines[0] || line == lines[len(lines)-1]) {
			continue
		}
		fmt.Fprintln(u.w, u.bannerColorize(line))
	}
	fmt.Fprintln(u.w)
	if tagline != "" {
		fmt.Fprintln(u.w, u.White("  "+tagline))
	}
	fmt.Fprintln(u.w, u.Teal("  QYVORA — https://qyvora.com"))
	fmt.Fprintln(u.w)
}

// BannerFoot prints the version and help hint.
func (u *UI) BannerFoot(ver string) {
	u.Status(">", "v %s", ver)
	fmt.Fprintln(u.w, u.DimWhite("  type 'help' for commands, 'exit' to leave."))
	fmt.Fprintln(u.w)
}

// HUD prints the single-line status bar.
func (u *UI) HUD(iface, mode, cwd, ver string) {
	if !u.color {
		return
	}
	kv := func(k, v string) string { return u.DimWhite(k+" ") + u.White(v) }
	left := kv("interface", iface) + u.DimWhite("  ·  ") + kv("mode", mode) + u.DimWhite("  ·  ") + kv("cwd", cwd)
	right := u.Teal("v " + ver)
	cols := u.width
	if cols < 20 {
		cols = 80
	}
	pad := cols - len(left) - len(right) - 1
	if pad < 1 {
		pad = 1
	}
	fmt.Fprintf(u.w, "%s %s%s\n", u.paint("▮", ansiBold+ansiTeal), left, strings.Repeat(" ", pad)+right)
}

// Table prints a simple two-space-aligned table.
func (u *UI) Table(headers []string, rows [][]string) {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, c := range row {
			if i < len(widths) && len(c) > widths[i] {
				widths[i] = len(c)
			}
		}
	}
	for i, h := range headers {
		fmt.Fprintf(u.w, "%-*s  ", widths[i], strings.ToUpper(h))
	}
	fmt.Fprintln(u.w)
	for _, row := range rows {
		for i, c := range row {
			if i < len(widths) {
				fmt.Fprintf(u.w, "%-*s  ", widths[i], c)
			}
		}
		fmt.Fprintln(u.w)
	}
}

// Prompt returns the interactive prompt string.
func (u *UI) Prompt(name, target string) string {
	if target == "" {
		target = "none"
	}
	return u.BoldTeal(name+" ") + u.DimWhite("("+target+") ") + u.Teal("> ")
}

func (u *UI) bannerColorize(line string) string {
	if !u.color {
		return line
	}
	var b strings.Builder
	for _, r := range line {
		switch r {
		case '@', '%', '#':
			b.WriteString(ansiTeal + string(r) + ansiReset)
		case '*', '+':
			b.WriteString(ansiDark + string(r) + ansiReset)
		case '=', '-', ':', '.':
			b.WriteString(ansiDim + ansiWhite + string(r) + ansiReset)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func padTo(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}
