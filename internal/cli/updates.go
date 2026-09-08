package cli

import (
	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-mansa/internal/selfupdate"
	"github.com/QYVORA/qyvora-mansa/internal/version"
)

// newUpdatesCmd checks for and installs Mansa updates.
func newUpdatesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "updates",
		Aliases: []string{"update"},
		Short:   "Check for and install Mansa updates",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := selfupdate.Config{
				Owner:          "QYVORA",
				Repo:           "qyvora-mansa",
				ToolName:       "mansa",
				CurrentVersion: func() string { return version.Version },
			}
			result := selfupdate.Run(cmd.Context(), cfg, cmd.OutOrStdout())
			if appState.Printer.Format() != "terminal" {
				appState.Printer.Print(result)
				return nil
			}
			switch result.Status {
			case selfupdate.StatusUpdated:
				cmd.PrintErrf("Mansa updated to %s\n", result.Latest)
			case selfupdate.StatusCurrent:
				cmd.Printf("Mansa is up to date (%s)\n", result.Current)
			default:
				cmd.PrintErrf("%s\n", result.Error)
			}
			return nil
		},
	}
	return cmd
}
