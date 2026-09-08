package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-mansa/internal/pipeline"
	"github.com/QYVORA/qyvora-mansa/internal/reporting"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// simFlag tracks the shared --sim flag across assessment commands.
func registerScopeFlags(cmd *cobra.Command) {
	cmd.Flags().Bool("sim", false, "use the offline deterministic simulation dataset")
	cmd.Flags().String("interface", "", "wireless interface to assess (default: from config)")
	cmd.Flags().String("ssid", "", "filter access points by SSID")
	cmd.Flags().String("bssid", "", "filter access points by BSSID")
	cmd.Flags().String("band", "", "filter access points by band (2.4GHz, 5GHz, 6GHz)")
}

// establishTarget resolves, authorizes, and returns a target for a run.
func establishTarget(cmd *cobra.Command) (*models.Target, error) {
	f := cmd.Flags()
	sim, _ := f.GetBool("sim")
	iface, _ := f.GetString("interface")
	ssid, _ := f.GetString("ssid")
	bssid, _ := f.GetString("bssid")
	iface, _ = resolveInterfaceFromFilters(sim, iface, ssid, bssid)
	t, err := appState.EstablishTarget(sim, iface, ssid, bssid)
	if err != nil {
		return nil, err
	}
	if !sim {
		if _, err := appState.Authorize(t, authorizedFrom(cmd)); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func resolveInterfaceFromFilters(sim bool, iface, _ string, _ string) (string, error) {
	if sim {
		return "wlan0", nil
	}
	if iface != "" {
		return iface, nil
	}
	return appState.Cfg.GetString("wireless.interface"), nil
}

func newAssessCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "assess",
		Aliases: []string{"scan-all"},
		Short:   "Run the full wireless assessment pipeline",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			t, err := establishTarget(cmd)
			if err != nil {
				return usageErr(err)
			}
			sim, _ := cmd.Flags().GetBool("sim")
			sess, err := appState.RunPipeline(ctxOf(cmd), t, sim)
			if err != nil {
				return err
			}
			if sess != nil {
				renderSessionSummary(cmd, sess)
			}
			return nil
		},
	}
	registerScopeFlags(cmd)
	return cmd
}

func newDiscoverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Discover wireless interfaces and capabilities",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			sim, _ := cmd.Flags().GetBool("sim")
			t, err := establishTarget(cmd)
			if err != nil {
				return usageErr(err)
			}
			sess, err := appState.RunPipelineStage(ctxOf(cmd), t, sim, pipeline.StageDiscover)
			if err != nil {
				return err
			}
			renderInterfaces(cmd, sess)
			return nil
		},
	}
	cmd.Flags().Bool("sim", false, "use the offline deterministic simulation dataset")
	cmd.Flags().String("interface", "", "wireless interface to inspect")
	return cmd
}

func newScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan for wireless networks and access points",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			t, err := establishTarget(cmd)
			if err != nil {
				return usageErr(err)
			}
			sim, _ := cmd.Flags().GetBool("sim")
			sess, err := appState.RunPipelineStage(ctxOf(cmd), t, sim, pipeline.StageEnumerate)
			if err != nil {
				return err
			}
			renderAccessPoints(cmd, sess)
			return nil
		},
	}
	registerScopeFlags(cmd)
	return cmd
}

func newEnumerateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate access-point inventory with filtering",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			t, err := establishTarget(cmd)
			if err != nil {
				return usageErr(err)
			}
			sim, _ := cmd.Flags().GetBool("sim")
			sess, err := appState.RunPipelineStage(ctxOf(cmd), t, sim, pipeline.StageEnumerate)
			if err != nil {
				return err
			}
			renderAccessPoints(cmd, sess)
			return nil
		},
	}
	registerScopeFlags(cmd)
	return cmd
}

func newObserveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "observe",
		Short: "Observe wireless clients/stations and observations",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			t, err := establishTarget(cmd)
			if err != nil {
				return usageErr(err)
			}
			sim, _ := cmd.Flags().GetBool("sim")
			sess, err := appState.RunPipelineStage(ctxOf(cmd), t, sim, pipeline.StageObserve)
			if err != nil {
				return err
			}
			renderStations(cmd, sess)
			return nil
		},
	}
	registerScopeFlags(cmd)
	return cmd
}

func newAnalyzeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Analyze the latest session for security findings",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			sess, err := appState.LoadSession(sessionFlag(cmd))
			if err != nil {
				return fmt.Errorf("no session to analyze: %w", err)
			}
			analyzed, err := appState.AnalyzeSession(ctxOf(cmd), sess)
			if err != nil {
				return err
			}
			renderSessionSummary(cmd, analyzed)
			return nil
		},
	}
	cmd.Flags().String("session", "", "session ID (default: latest)")
	return cmd
}

func usageErr(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("target error: %w", err)
}

// sessionFlag resolves a --session flag value ("" = latest).
func sessionFlag(cmd *cobra.Command) string {
	v, _ := cmd.Flags().GetString("session")
	return v
}

// renderSessionSummary prints a compact session summary in terminal mode.
func renderSessionSummary(cmd *cobra.Command, sess *models.Session) {
	if sess == nil {
		return
	}
	if appState.Printer.Format() != "terminal" {
		appState.Printer.Print(sess)
		return
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Session %s (%s)\n", sess.ID, sess.Target)
	fmt.Fprintf(out, "  Access points: %d\n", len(sess.AccessPoints))
	fmt.Fprintf(out, "  Stations:      %d\n", len(sess.Stations))
	fmt.Fprintf(out, "  Findings:      %d\n", len(sess.Findings))
	fmt.Fprintf(out, "  Risk:          %d/100 (%s)\n", sess.RiskScore, sess.RiskLevel)
}

// renderInterfaces prints discovered interfaces.
func renderInterfaces(cmd *cobra.Command, sess *models.Session) {
	if sess == nil {
		return
	}
	if appState.Printer.Format() != "terminal" {
		appState.Printer.Print(sess.Interfaces)
		return
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Discovered %d wireless interface(s)\n\n", len(sess.Interfaces))
	rows := make([][]string, 0, len(sess.Interfaces))
	for _, iface := range sess.Interfaces {
		rows = append(rows, []string{iface.Name, iface.State, iface.Mode, joinBands(iface.Supported)})
	}
	appState.Printer.PrintTable([]string{"interface", "state", "mode", "bands"}, rows)
}

// renderAccessPoints prints access points with optional filters.
func renderAccessPoints(cmd *cobra.Command, sess *models.Session) {
	if sess == nil {
		return
	}
	if appState.Printer.Format() != "terminal" {
		appState.Printer.Print(sess.AccessPoints)
		return
	}
	out := cmd.OutOrStdout()
	ssid, _ := cmd.Flags().GetString("ssid")
	bssid, _ := cmd.Flags().GetString("bssid")
	band, _ := cmd.Flags().GetString("band")
	aps := pipeline.FilterBySSID(sess.AccessPoints, ssid)
	aps = pipeline.FilterByBSSID(aps, bssid)
	aps = pipeline.FilterByBand(aps, band)
	fmt.Fprintf(out, "Discovered %d access point(s)\n\n", len(aps))
	rows := make([][]string, 0, len(aps))
	for _, ap := range aps {
		sec := ap.Security.Auth
		if sec == "" {
			sec = "open"
		}
		rows = append(rows, []string{ap.BSSID, ap.SSID, fmt.Sprintf("%d", ap.Channel), ap.Band,
			fmt.Sprintf("%d", ap.Signal), sec, ap.Vendor})
	}
	appState.Printer.PrintTable([]string{"bssid", "ssid", "ch", "band", "signal", "security", "vendor"}, rows)
}

// renderStations prints observed stations.
func renderStations(cmd *cobra.Command, sess *models.Session) {
	if sess == nil {
		return
	}
	if appState.Printer.Format() != "terminal" {
		appState.Printer.Print(sess.Stations)
		return
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Observed %d station(s)\n\n", len(sess.Stations))
	rows := make([][]string, 0, len(sess.Stations))
	for _, st := range sess.Stations {
		rows = append(rows, []string{st.MAC, st.APBSSID, fmt.Sprintf("%d", st.Signal), joinStrings(st.ProbedSSIDs)})
	}
	appState.Printer.PrintTable([]string{"mac", "ap", "signal", "probed ssids"}, rows)
}

func joinBands(ss []string) string { return joinStrings(ss) }

func joinStrings(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

var _ = reporting.FormatTerminal
