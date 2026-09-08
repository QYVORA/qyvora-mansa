// Package reporting renders Mansa sessions into terminal, markdown, HTML,
// JSON, and YAML reports.
package reporting

import (
	"encoding/json"
	"fmt"
	"html"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// Format is a report output format.
type Format string

const (
	FormatTerminal Format = "terminal"
	FormatMarkdown Format = "markdown"
	FormatHTML     Format = "html"
	FormatJSON     Format = "json"
	FormatYAML     Format = "yaml"
)

// ParseFormat parses a report format string.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "terminal":
		return FormatTerminal, nil
	case "markdown", "md":
		return FormatMarkdown, nil
	case "html":
		return FormatHTML, nil
	case "json":
		return FormatJSON, nil
	case "yaml":
		return FormatYAML, nil
	default:
		return "", fmt.Errorf("unknown report format %q", s)
	}
}

// Render renders a session in the requested format.
func Render(s *models.Session, format Format) (string, error) {
	switch format {
	case FormatJSON:
		b, err := json.MarshalIndent(s, "", "  ")
		return string(b), err
	case FormatYAML:
		b, err := json.MarshalIndent(s, "", "  ")
		if err != nil {
			return "", err
		}
		var raw any
		if err := yaml.Unmarshal(b, &raw); err != nil {
			return "", err
		}
		y, err := yaml.Marshal(raw)
		return string(y), err
	case FormatHTML:
		return renderHTML(s), nil
	case FormatMarkdown:
		return renderMarkdown(s), nil
	default:
		return renderTerminal(s), nil
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func renderTerminal(s *models.Session) string {
	var b strings.Builder
	writef := func(format string, a ...any) {
		fmt.Fprintf(&b, format+"\n", a...)
	}
	writef("mansa wireless security report")
	writef("  Session:   %s", s.ID)
	writef("  Target:    %s", s.Target)
	writef("  Interface: %s", orDash(s.Interface))
	writef("  Started:   %s", s.Start.Format("2006-01-02 15:04:05"))
	writef("  Finished:  %s", orDash(s.End.Format("2006-01-02 15:04:05")))
	writef("  Offline:   %v", s.Offline)
	writef("  Risk:      %d/100 (%s)", s.RiskScore, s.RiskLevel)
	writef("")
	writef("Discovered access points: %d", len(s.AccessPoints))
	writef("Discovered stations:     %d", len(s.Stations))
	writef("Findings:                %d", len(s.Findings))
	writef("Evidence:                %d", len(s.Evidence))
	writef("")
	for _, ap := range s.AccessPoints {
		writef("AP  %s  %s  ch=%d %s  sig=%d dBm  %s",
			ap.BSSID, orDash(ap.SSID), ap.Channel, ap.Band, ap.Signal, orDash(ap.Security.Auth))
	}
	writef("")
	writef("Findings:")
	for _, f := range s.Findings {
		writef("  [%s] %s (%s)", strings.ToUpper(string(f.Severity)), f.Title, f.RuleID)
		writef("      confidence=%s target=%s", f.Confidence, f.Target)
	}
	for _, e := range s.Errors {
		writef("  error: %s", e)
	}
	return b.String()
}

func renderMarkdown(s *models.Session) string {
	var b strings.Builder
	writef := func(format string, a ...any) {
		fmt.Fprintf(&b, format+"\n", a...)
	}
	writef("# Mansa Wireless Security Report")
	writef("")
	writef("| Field | Value |")
	writef("| --- | --- |")
	writef("| Session | %s |", s.ID)
	writef("| Target | %s |", s.Target)
	writef("| Interface | %s |", orDash(s.Interface))
	writef("| Started | %s |", s.Start.Format("2006-01-02 15:04:05"))
	writef("| Finished | %s |", orDash(s.End.Format("2006-01-02 15:04:05")))
	writef("| Offline | %v |", s.Offline)
	writef("| Risk | %d/100 (%s) |", s.RiskScore, s.RiskLevel)
	writef("")
	writef("## Access Points (%d)", len(s.AccessPoints))
	writef("")
	writef("| BSSID | SSID | Channel | Band | Signal | Security |")
	writef("| --- | --- | --- | --- | --- | --- |")
	for _, ap := range s.AccessPoints {
		writef("| %s | %s | %d | %s | %d | %s |",
			escapeMD(ap.BSSID), escapeMD(orDash(ap.SSID)), ap.Channel, ap.Band, ap.Signal, escapeMD(orDash(ap.Security.Auth)))
	}
	writef("")
	writef("## Stations (%d)", len(s.Stations))
	writef("")
	writef("| MAC | AP | Signal |")
	writef("| --- | --- | --- |")
	for _, st := range s.Stations {
		writef("| %s | %s | %d |", st.MAC, st.APBSSID, st.Signal)
	}
	writef("")
	writef("## Findings (%d)", len(s.Findings))
	writef("")
	for _, f := range s.Findings {
		writef("- **[%s]** %s (`%s`) — %s", strings.ToUpper(string(f.Severity)), f.Title, f.RuleID, escapeMD(f.Description))
		for _, e := range f.Evidence {
			writef("  - evidence: %s", escapeMD(e.Detail))
		}
	}
	return b.String()
}

func renderHTML(s *models.Session) string {
	var b strings.Builder
	writef := func(format string, a ...any) {
		fmt.Fprintf(&b, format+"\n", a...)
	}
	writef("<html><head><title>Mansa Wireless Security Report</title>")
	writef("<style>body{font-family:sans-serif}table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:4px 8px}th{background:#e6fff9}</style>")
	writef("</head><body>")
	writef("<h1>Mansa Wireless Security Report</h1>")
	writef("<p>Session: %s | Target: %s | Risk: %d/100 (%s)</p>", html.EscapeString(s.ID), html.EscapeString(s.Target), s.RiskScore, html.EscapeString(s.RiskLevel))
	if len(s.AccessPoints) > 0 {
		writef("<h2>Access Points</h2><table><tr><th>BSSID</th><th>SSID</th><th>Ch</th><th>Band</th><th>Signal</th><th>Security</th></tr>")
		for _, ap := range s.AccessPoints {
			writef("<tr><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td>%d</td><td>%s</td></tr>",
				html.EscapeString(ap.BSSID), html.EscapeString(orDash(ap.SSID)), ap.Channel, ap.Band, ap.Signal, html.EscapeString(orDash(ap.Security.Auth)))
		}
		writef("</table>")
	}
	if len(s.Findings) > 0 {
		writef("<h2>Findings</h2><table><tr><th>Severity</th><th>Title</th><th>Rule</th><th>Target</th></tr>")
		for _, f := range s.Findings {
			writef("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
				html.EscapeString(string(f.Severity)), html.EscapeString(f.Title), html.EscapeString(f.RuleID), html.EscapeString(f.Target))
		}
		writef("</table>")
	}
	writef("</body></html>")
	return b.String()
}

func escapeMD(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}
