package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-mansa/internal/capabilities"
	"github.com/QYVORA/qyvora-mansa/internal/version"
)

func newCapabilitiesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "capabilities",
		Aliases: []string{"caps"},
		Short:   "List the machine-readable capability contract",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			list := appState.Capabilities()
			if appState.Printer.Format() != "terminal" {
				appState.Printer.Print(list)
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Mansa %s — wireless security capability contract\n\n", version.Version)
			rows := make([][]string, 0, len(list))
			for _, c := range list {
				rows = append(rows, []string{c.ID, c.Category, c.Risk, boolStr(c.AuthRequired)})
			}
			appState.Printer.PrintTable([]string{"id", "category", "risk", "auth"}, rows)
			return nil
		},
	}
	return cmd
}

func boolStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

var _ = capabilities.ContractVersion
