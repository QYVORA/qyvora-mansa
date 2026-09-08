package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// newTargetCmd manages targets.
func newTargetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "target",
		Short: "Manage assessment targets",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			list := appState.Targets.List()
			if appState.Printer.Format() != "terminal" {
				appState.Printer.Print(list)
				return nil
			}
			if len(list) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No saved targets.")
				return nil
			}
			rows := make([][]string, 0, len(list))
			for _, t := range list {
				auth := "no"
				if t.Authorized() {
					auth = "yes"
				}
				rows = append(rows, []string{t.ID, string(t.Type), t.Value, t.Interface, auth})
			}
			appState.Printer.PrintTable([]string{"id", "type", "value", "interface", "authorized"}, rows)
			return nil
		},
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List saved targets",
		RunE:  cmd.RunE,
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "current",
		Short: "Show the current target",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			t := appState.Targets.Current()
			if t == nil {
				fmt.Fprintln(cmd.OutOrStdout(), "No current target.")
				return nil
			}
			if appState.Printer.Format() != "terminal" {
				appState.Printer.Print(t)
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Current target: %s (%s)\n", t.DisplayName(), t.ID)
			fmt.Fprintf(cmd.OutOrStdout(), "  Authorized:  %v\n", t.Authorized())
			return nil
		},
	})
	return cmd
}

var _ = models.TargetInterface
