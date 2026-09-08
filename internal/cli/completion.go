package cli

import (
	"github.com/spf13/cobra"
)

// newCompletionCmd generates shell completion scripts.
func newCompletionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion scripts",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			shell := args[0]
			switch shell {
			case "bash":
				return root().GenBashCompletion(cmd.OutOrStdout())
			case "zsh":
				return root().GenZshCompletion(cmd.OutOrStdout())
			case "fish":
				return root().GenFishCompletion(cmd.OutOrStdout(), true)
			case "powershell":
				return root().GenPowerShellCompletion(cmd.OutOrStdout())
			default:
				return usagef("unsupported shell %q (bash, zsh, fish, powershell)", shell)
			}
		},
	}
	return cmd
}

// root returns a fresh root command for completion generation.
func root() *cobra.Command { return newRootCmd() }
