package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-mansa/internal/capabilities"
	"github.com/QYVORA/qyvora-mansa/internal/transport"
	"github.com/QYVORA/qyvora-mansa/internal/version"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

func newCapabilitiesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "capabilities",
		Aliases: []string{"caps"},
		Short:   "List the machine-readable capability contract",
		Long: "List the machine-readable capability contract.\n\n" +
			"Without flags this prints what the binary implements. --hardware adds a\n" +
			"separate column for what the current host actually offers, so a capability\n" +
			"that is implemented and unavailable are never confused. --sim requires\n" +
			"--hardware.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			withHardware, _ := cmd.Flags().GetBool("hardware")
			simulated, _ := cmd.Flags().GetBool("sim")
			if simulated && !withHardware {
				return usagef("--sim requires --hardware: a simulated hardware view must be asked for explicitly")
			}

			list := appState.Capabilities()
			if withHardware {
				report, err := hardwareReport(ctxOf(cmd), simulated)
				if err != nil {
					return err
				}
				if appState.Printer.Format() != "terminal" {
					appState.Printer.Print(report)
					return nil
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Mansa %s — wireless security capability contract\n\n", version.Version)
				rows := make([][]string, 0, len(list))
				for _, tool := range list {
					tier := string(tool.Tier)
					if tier == "" {
						tier = "-"
					}
					noise := string(tool.NoiseLevel)
					if noise == "" {
						noise = "-"
					}
					state, reason := hardwareStateFor(tool.HardwareCapability, report)
					if reason != "" {
						rows = append(rows, []string{tool.ID, tier, noise, tool.Risk, boolStr(tool.AuthRequired), string(state), reason})
						continue
					}
					rows = append(rows, []string{tool.ID, tier, noise, tool.Risk, boolStr(tool.AuthRequired), string(state), ""})
				}
				appState.Printer.PrintTable([]string{"id", "tier", "noise", "risk", "auth", "hardware", "reason"}, rows)
				return nil
			}
			if appState.Printer.Format() != "terminal" {
				appState.Printer.Print(list)
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Mansa %s — wireless security contract\n\n", version.Version)
			rows := make([][]string, 0, len(list))
			for _, c := range list {
				tier := string(c.Tier)
				if tier == "" {
					tier = "-"
				}
				noise := string(c.NoiseLevel)
				if noise == "" {
					noise = "-"
				}
				rows = append(rows, []string{c.ID, tier, noise, c.Risk, boolStr(c.AuthRequired)})
			}
			appState.Printer.PrintTable([]string{"id", "tier", "noise", "risk", "auth"}, rows)
			return nil
		},
	}
	cmd.Flags().Bool("hardware", false, "report what the current host offers alongside what is implemented")
	cmd.Flags().Bool("sim", false, "report the simulated hardware view; requires --hardware")
	return cmd
}

// hardwareReport resolves the provider to inspect.
//
// A simulated view always uses the fixture provider, so --sim cannot read the
// real host's interfaces and cannot be mistaken for an observation of them.
func hardwareReport(ctx context.Context, simulated bool) (models.HardwareReport, error) {
	var backend transport.Backend
	switch {
	case simulated:
		backend = transport.New()
	case appState != nil && appState.Backend != nil:
		backend = appState.Backend
	default:
		backend = transport.NewLinux()
	}
	reporter, ok := backend.(transport.CapabilityReporter)
	if !ok {
		return models.HardwareReport{}, usagef("provider %s cannot report hardware availability", backend.Name())
	}
	return reporter.HardwareReport(ctx)
}

// hardwareStateFor reports what the host offers for one capability.
//
// The join is on the capability's declared HardwareCapability, never on the
// capability's own id. The two namespaces are deliberately different: the
// contract publishes tools such as mansa.scan, while a provider reports what it
// can do such as wifi.ap_enumeration. Joining the two on id alone matches
// nothing, which would report every capability as unknown while looking exactly
// like a successful query.
//
// A tool that declares no hardware reads a file, a session, or a report, so it
// reports not_applicable rather than unknown. Calling that unknown would suggest
// the host might still be missing something it never needed.
func hardwareStateFor(hardwareCapability string, report models.HardwareReport) (models.CapabilityState, string) {
	if hardwareCapability == "" {
		return models.CapabilityNotApplicable, "reads a file, a session, or a report; it needs no radio"
	}
	for _, capability := range report.Capabilities {
		if capability.ID == hardwareCapability {
			return capability.Hardware, capability.Reason
		}
	}
	// The provider did not report a state for a capability the contract claims
	// depends on it. That is a real gap, so it says so rather than appearing
	// merely unavailable.
	return models.CapabilityUnknown, "the provider reported no state for " + hardwareCapability
}

func boolStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

var _ = capabilities.ContractVersion
