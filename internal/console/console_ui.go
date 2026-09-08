package console

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/QYVORA/qyvora-mansa/internal/banner"
)

// consoleUI wraps terminal rendering for the Mansa console with the brand
// teal accent. Color is enabled only on a TTY without NO_COLOR.
type consoleUI struct {
	w     io.Writer
	color bool
	width int
}

const (
	ansiReset = "\x1b[0m"
	ansiBold  = "\x1b[1m"
	ansiDim   = "\x1b[2m"
	ansiTeal  = "\x1b[38;2;0;186;163m"
	ansiDark  = "\x1b[38;2;0;140;120m"
	ansiWhite = "\x1b[37m"
	ansiRed   = "\x1b[31m"
	ansiAmber = "\x1b[33m"
)

func newConsoleUI(w io.Writer) *consoleUI {
	u := &consoleUI{w: w, width: 60}
	if f, ok := w.(*os.File); ok {
		info, err := f.Stat()
		if err == nil && info.Mode()&os.ModeCharDevice != 0 {
			u.color = true
		}
	}
	if noColor() {
		u.color = false
	}
	return u
}

func (u *consoleUI) paint(s, code string) string {
	if !u.color || s == "" {
		return s
	}
	return code + s + ansiReset
}

func (u *consoleUI) BoldTeal(s string) string { return u.paint(s, ansiBold+ansiTeal) }
func (u *consoleUI) DimWhite(s string) string { return u.paint(s, ansiDim+ansiWhite) }
func (u *consoleUI) Teal(s string) string     { return u.paint(s, ansiTeal) }

// Glyph renders a status glyph.
func (u *consoleUI) Glyph(g string) string {
	switch g {
	case "+":
		return u.paint("[+] ", ansiTeal)
	case "*":
		return u.paint("[*] ", ansiBold+ansiTeal)
	case "!":
		return u.paint("[!] ", ansiAmber)
	case "x":
		return u.paint("[x] ", ansiRed)
	case ">":
		return u.paint("[>] ", ansiWhite)
	default:
		return u.paint("["+g+"] ", ansiBold+ansiWhite)
	}
}

// Status prints a glyph-prefixed status line.
func (u *consoleUI) Status(g, format string, args ...any) {
	fmt.Fprintf(u.w, "%s%s\n", u.Glyph(g), fmt.Sprintf(format, args...))
}

// KV prints a key-value line.
func (u *consoleUI) KV(k, v string) {
	fmt.Fprintf(u.w, "%s  %s\n", u.DimWhite(padTo(k+":", 20)), u.whiteOr(v))
}

// Section prints a section header.
func (u *consoleUI) Section(title string) {
	fmt.Fprintf(u.w, "\n%s\n", u.BoldTeal("  "+strings.ToUpper(title)))
}

// Table prints an aligned table.
func (u *consoleUI) Table(headers []string, rows [][]string) {
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

// HUD prints the status bar.
func (u *consoleUI) HUD(iface, mode, _ string, ver string) {
	if !u.color {
		return
	}
	left := u.DimWhite("iface ") + u.whiteOr(iface) + u.DimWhite("  ·  ") +
		u.DimWhite("mode ") + u.whiteOr(mode) + u.DimWhite("  ·  ") + u.DimWhite("mansa")
	right := u.Teal("v " + ver)
	pad := 60 - len(left) - len(right) - 1
	if pad < 1 {
		pad = 1
	}
	fmt.Fprintf(u.w, "%s %s%s\n", u.paint("▮", ansiBold+ansiTeal), left, strings.Repeat(" ", pad)+right)
}

// Banner prints the canonical Mansa banner.
func (u *consoleUI) Banner(tagline string) {
	fmt.Fprintln(u.w)
	for _, line := range strings.Split(banner.Art, "\n") {
		fmt.Fprintln(u.w, u.colorize(line))
	}
	fmt.Fprintln(u.w)
	if tagline != "" {
		fmt.Fprintln(u.w, u.whiteOr("  "+tagline))
	}
	fmt.Fprintln(u.w, u.Teal("  QYVORA — https://qyvora.com"))
	fmt.Fprintln(u.w)
}

// BannerFoot prints version + hint.
func (u *consoleUI) BannerFoot(ver string) {
	u.Status(">", "v %s", ver)
	fmt.Fprintln(u.w, u.DimWhite("  type 'help' for commands, 'exit' to leave."))
	fmt.Fprintln(u.w)
}

func (u *consoleUI) colorize(line string) string {
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

func (u *consoleUI) whiteOr(s string) string {
	if u.color {
		return ansiWhite + s + ansiReset
	}
	return s
}

func padTo(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}

// noColor reports NO_COLOR presence.
func noColor() bool {
	return os.Getenv("NO_COLOR") != ""
}
