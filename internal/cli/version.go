package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if formatFlag == "json" || appState.Printer.Format() == "json" {
				appState.Printer.Print(appState.VersionJSON())
				return nil
			}
			fmt.Fprintln(cmd.OutOrStdout(), appState.VersionInfo())
			return nil
		},
	}
}
