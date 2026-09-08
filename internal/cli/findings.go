package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-mansa/internal/reporting"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// newFindingsCmd lists findings from the current/latest session.
func newFindingsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "findings",
		Short: "Show findings from a session",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := ""
			if len(args) > 0 {
				id = args[0]
			}
			sess, err := appState.LoadSession(id)
			if err != nil {
				return fmt.Errorf("no session: %w", err)
			}
			if appState.Printer.Format() != "terminal" {
				appState.Printer.Print(nonNilFindings(sess.Findings))
				return nil
			}
			if len(sess.Findings) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No findings in session "+sess.ID+".")
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Findings for session %s (risk %d/100 %s)\n\n", sess.ID, sess.RiskScore, sess.RiskLevel)
			rows := make([][]string, 0, len(sess.Findings))
			for _, f := range sess.SortedFindings() {
				rows = append(rows, []string{
					f.ID, f.RuleID, f.Title, string(f.Severity), string(f.Confidence), f.Target,
				})
			}
			appState.Printer.PrintTable([]string{"id", "rule", "title", "severity", "confidence", "target"}, rows)
			return nil
		},
	}
	return cmd
}

// newEvidenceCmd lists evidence from a session.
func newEvidenceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "evidence",
		Short: "Show evidence collected in a session",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := ""
			if len(args) > 0 {
				id = args[0]
			}
			sess, err := appState.LoadSession(id)
			if err != nil {
				return fmt.Errorf("no session: %w", err)
			}
			if appState.Printer.Format() != "terminal" {
				appState.Printer.Print(nonNilEvidence(sess.Evidence))
				return nil
			}
			if len(sess.Evidence) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No evidence in session "+sess.ID+".")
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Evidence for session %s\n\n", sess.ID)
			rows := make([][]string, 0, len(sess.Evidence))
			for _, e := range sess.Evidence {
				rows = append(rows, []string{e.ID, string(e.Kind), e.Source, e.Target, e.Detail})
			}
			appState.Printer.PrintTable([]string{"id", "kind", "source", "target", "detail"}, rows)
			return nil
		},
	}
	return cmd
}

// newReportCmd renders the report for a session.
func newReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Render a formatting report for a session",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := ""
			if len(args) > 0 {
				id = args[0]
			}
			sess, err := appState.LoadSession(id)
			if err != nil {
				return fmt.Errorf("no session: %w", err)
			}
			format, _ := cmd.Flags().GetString("format")
			if format == "" {
				format = "terminal"
			}
			f, err := reporting.ParseFormat(format)
			if err != nil {
				return err
			}
			content, err := reporting.Render(sess, f)
			if err != nil {
				return err
			}
			outPath, _ := cmd.Flags().GetString("out")
			if outPath != "" {
				if err := os.MkdirAll(filepath.Dir(outPath), 0o750); err != nil {
					return err
				}
				return os.WriteFile(outPath, []byte(content), 0o644)
			}
			fmt.Fprintln(cmd.OutOrStdout(), content)
			return nil
		},
	}
	cmd.Flags().StringP("format", "f", "terminal", "report format: terminal, json, markdown, html, yaml")
	cmd.Flags().String("out", "", "write the report to this path instead of stdout")
	return cmd
}

// newSessionCmd manages and lists sessions.
func newSessionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Inspect saved sessions",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				sess, err := appState.LoadSession(args[0])
				if err != nil {
					return fmt.Errorf("no session: %w", err)
				}
				if appState.Printer.Format() != "terminal" {
					appState.Printer.Print(sess)
					return nil
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Session %s\n", sess.ID)
				fmt.Fprintf(cmd.OutOrStdout(), "  Target:    %s\n", sess.Target)
				fmt.Fprintf(cmd.OutOrStdout(), "  Interface: %s\n", sess.Interface)
				fmt.Fprintf(cmd.OutOrStdout(), "  Started:   %s\n", sess.Start.Format("2006-01-02 15:04:05"))
				fmt.Fprintf(cmd.OutOrStdout(), "  Offline:   %v\n", sess.Offline)
				fmt.Fprintf(cmd.OutOrStdout(), "  APs:       %d\n", len(sess.AccessPoints))
				fmt.Fprintf(cmd.OutOrStdout(), "  Findings:  %d\n", len(sess.Findings))
				fmt.Fprintf(cmd.OutOrStdout(), "  Risk:      %d/100 (%s)\n", sess.RiskScore, sess.RiskLevel)
				return nil
			}
			ids, err := appState.Store.List()
			if err != nil {
				return err
			}
			if appState.Printer.Format() != "terminal" {
				appState.Printer.Print(ids)
				return nil
			}
			if len(ids) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No sessions yet. Run `mansa assess --sim` or `mansa scan --sim` first.")
				return nil
			}
			rows := make([][]string, 0, len(ids))
			for _, id := range ids {
				sess, _ := appState.LoadSession(id)
				if sess == nil {
					rows = append(rows, []string{id, "-", "-", "-"})
					continue
				}
				rows = append(rows, []string{id, sess.Target, fmt.Sprintf("%d", len(sess.Findings)),
					fmt.Sprintf("%d (%s)", sess.RiskScore, sess.RiskLevel)})
			}
			appState.Printer.PrintTable([]string{"session", "target", "findings", "risk"}, rows)
			return nil
		},
	}
	return cmd
}

// newEventsCmd replays the events of a session from its JSON store.
func newEventsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "events",
		Short: "Show stored events for a session",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := ""
			if len(args) > 0 {
				id = args[0]
			}
			sess, err := appState.LoadSession(id)
			if err != nil {
				return fmt.Errorf("no session: %w", err)
			}
			data, _ := marshalSession(sess)
			if appState.Printer.Format() == "json" || appState.Printer.Format() == "yaml" {
				appState.Printer.Print(map[string]any{"session": sess.ID, "data": string(data)})
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Session %s completed %d stage(s)\n", sess.ID, len(sess.Stages))
			rows := make([][]string, 0, len(sess.Stages))
			for _, s := range sess.Stages {
				rows = append(rows, []string{s, "completed"})
			}
			appState.Printer.PrintTable([]string{"stage", "status"}, rows)
			if len(sess.Errors) > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "\nErrors:\n")
				for _, e := range sess.Errors {
					fmt.Fprintf(cmd.OutOrStdout(), "  ! %s\n", e)
				}
			}
			_ = data
			return nil
		},
	}
	return cmd
}

// nonNilFindings ensures a JSON-printable slice.
func nonNilFindings(f []models.Finding) any {
	if f == nil {
		return []models.Finding{}
	}
	return f
}

// nonNilEvidence ensures a JSON-printable slice.
func nonNilEvidence(e []models.Evidence) any {
	if e == nil {
		return []models.Evidence{}
	}
	return e
}

func marshalSession(s *models.Session) ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

var _ = reporting.FormatJSON
