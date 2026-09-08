package console

import (
	"strings"
)

// Prompt returns the contextual prompt for the current session state.
func (c *Console) Prompt() string {
	var b strings.Builder
	b.WriteString("mansa")
	if c.iface != "" {
		b.WriteString(":")
		b.WriteString(c.iface)
	}
	if c.sim {
		b.WriteString(" ~sim")
	}
	if c.authorized && !c.sim {
		b.WriteString(" ~auth")
	}
	b.WriteString("> ")
	return b.String()
}
