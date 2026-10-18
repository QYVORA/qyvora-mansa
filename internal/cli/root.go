// Package mansa cli wires the mansa command tree, shared flags, exit-code
// handling, and cancellation. Execute never calls os.Exit; callers control
// process termination.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-mansa/internal/app"
	errs "github.com/QYVORA/qyvora-mansa/internal/errors"
	"github.com/QYVORA/qyvora-mansa/internal/exitcode"
	"github.com/QYVORA/qyvora-mansa/internal/output"
	"github.com/QYVORA/qyvora-mansa/internal/version"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// usageError marks a mistake in how mansa was invoked (exit 2).
type usageError struct{ err error }

func (u usageError) Error() string { return u.err.Error() }
func (u usageError) Unwrap() error { return u.err }

func usagef(format string, a ...any) error {
	return usageError{fmt.Errorf(format, a...)}
}

// App is the shared application state for both CLI and console.
var appState *app.AppState
var updateFlag bool

// consoleExitCode carries the console's exit code into ExecuteArgs.
var consoleExitCode int

// cliTerminalOut returns the destination for human terminal lines. When the
// event JSONL stream owns stdout (--events stdout), human lines go to stderr
// so the stream stays pure.
func cliTerminalOut(cmd *cobra.Command) io.Writer {
	if eventsFlag == "stdout" {
		return os.Stderr
	}
	return cmd.OutOrStdout()
}

// Execute runs the root command against os.Args and returns the exit code.
func Execute() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return ExecuteArgs(ctx, os.Args[1:])
}

// ExecuteArgs runs the root command with an explicit argument vector.
func ExecuteArgs(ctx context.Context, args []string) int {
	root := newRootCmd()
	root.SetContext(ctx)
	root.SetArgs(args)
	if appState == nil {
		appState = app.New("")
	}
	cobra.OnInitialize(initApp)

	if err := root.Execute(); err != nil {
		var exitErr *errs.ExitError
		if errors.As(err, &exitErr) {
			fmt.Fprintln(os.Stderr, "Error:", exitErr.Message)
			if exitErr.Cause != nil {
				fmt.Fprintln(os.Stderr, "  "+exitErr.Cause.Error())
			}
			return exitErr.Code
		}
		var ue usageError
		if errors.As(err, &ue) {
			fmt.Fprintln(os.Stderr, "Error:", ue.Error())
			return exitcode.Usage
		}
		if errors.Is(err, context.Canceled) {
			return exitcode.Interrupted
		}
		fmt.Fprintln(os.Stderr, "Error:", err.Error())
		return exitcode.Runtime
	}
	if consoleExitCode != 0 {
		return consoleExitCode
	}
	return exitcode.Success
}

func initApp() {
	if appState == nil {
		appState = app.New("")
	}
	appState.Init(formatFlag, eventsFlag, quietFlag, verboseFlag, dryRunFlag)
}

var (
	formatFlag    string
	eventsFlag    string
	quietFlag     bool
	verboseFlag   bool
	dryRunFlag    bool
	allowShellOut bool
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "mansa",
		Short: "Authorized wireless security assessment framework",
		Long: `mansa is a terminal-first wireless security assessment framework.

Commands follow the shared tier grammar
<tool> <tier> <module> [<action>] [target] [flags], where the tier is one
of recon, exploit, or report. Run it with no arguments to print this
help; assessment is one-shot, e.g. mansa recon scan --sim,
mansa recon analyze --session ... .

It performs authorized wireless discovery, access-point enumeration,
client observation, WLAN security analysis, channel/RF analysis, and
produces evidence-backed findings with transparent risk scoring.

Authorized use only: assess wireless networks you own or are authorized
to evaluate.`,
		Example: `  mansa recon scan --sim
  mansa recon bluetooth scan
  mansa exploit exploit list
  mansa report --format markdown
  mansa report findings`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.Version,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			if initErr := appInitErr(); initErr != nil {
				return errs.NewExitError(2, initErr.Error())
			}
			if eventsFlag == "stdout" && appState.Printer.Format() != output.FormatTerminal {
				// stdout must carry exactly one machine stream. With the event
				// JSONL stream owning stdout, a machine report format cannot
				// share it: use --events stderr or --events <file>.
				return usagef("cannot combine --events stdout with a machine report format; use --events stderr or --events <file>")
			}
			return nil
		},
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				return usagef("unknown command %q (try 'mansa --help')", args[0])
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			// The bare invocation is one-shot CLI only: print usage rather
			// than drop into an interactive interface. The per-tool TUI is
			// disabled pending the redirect of qyvora-tui to the future AI
			// orchestration layer.
			return cmd.Root().Help()
		},
	}
	pf := root.PersistentFlags()
	pf.BoolVar(&updateFlag, "update", false, "update the CLI to the latest official release")
	pf.StringVarP(&formatFlag, "output", "o", "", "output format: terminal, json, yaml, markdown, html")
	pf.BoolVar(&quietFlag, "quiet", false, "suppress non-error output")
	pf.BoolVarP(&verboseFlag, "verbose", "v", false, "verbose output")
	pf.StringVar(&eventsFlag, "events", "", "emit JSONL event stream to stdout, stderr, or a file path")
	pf.BoolVar(&dryRunFlag, "dry-run", false, "show the assessment plan without executing")
	pf.BoolVar(&allowShellOut, "allow-shellout", false, "allow scripts to use exec/run.cmd shell-out (also via QYVORA_ALLOW_SHELLOUT=1)")
	pf.BoolP("authorized", "y", false, "confirm authorization scope non-interactively")

	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return usageError{err}
	})
	root.SetVersionTemplate(fmt.Sprintf("mansa %s\n", version.Version))

	// Flat utility commands, identical in shape across all 14 tools.
	root.AddCommand(newVersionCmd(), newCapabilitiesCmd(), newCompletionCmd(), newUpdatesCmd(), newScriptCmd())

	// Tier grammar: <tool> <tier> <module> [<action>] [target] [flags]. mansa's
	// collection and validation work is recon-tier; its active-testing and
	// exploitation modules are exploit-tier; results surface as
	// findings/evidence/report. The tier parents always exist so the command
	// shape is uniform across tools.
	ops := newOperationCmds()

	recon := &cobra.Command{
		Use:   "recon",
		Short: "Discovery, enumeration, capture and validation modules",
	}
	recon.AddCommand(
		newAssessCmd(),
		newDiscoverCmd(),
		newScanCmd(),
		newEnumerateCmd(),
		newObserveCmd(),
		newAnalyzeCmd(),
		newTargetCmd(),
		newSessionCmd(),
		newEventsCmd(),
		newCaptureCmd(),
		newCredentialsCmd(),
		newBluetoothCmd(),
		ops[0],
	)

	exploit := &cobra.Command{
		Use:   "exploit",
		Short: "Active-testing and exploitation modules",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			// Back-compat: the pre-tier `mansa exploit <module>` and
			// `mansa exploit list` forms addressed the exploitation class
			// directly. The name now belongs to the tier, so preserve them.
			if args[0] == "list" {
				return newOperationListCmd(models.ClassExploitation).RunE(cmd, nil)
			}
			return runOperation(cmd, args[0], models.ClassExploitation)
		},
	}
	bindOperationFlags(exploit)
	exploit.AddCommand(ops[1], ops[2])

	report := newReportCmd()
	report.Short = "Render reports and inspect findings and evidence"
	report.AddCommand(newFindingsCmd(), newEvidenceCmd())

	root.AddCommand(recon, exploit, report)

	// Backward-compatible top-level aliases: the tier form is the supported
	// grammar, but every pre-tier invocation keeps resolving as a hidden
	// command so existing scripts are not broken. `report` and `exploit` are
	// themselves tier names, so their pre-tier forms are handled by the tiers
	// (report keeps its run behavior; exploit dispatches to the exploitation
	// class). Cobra does not suggest hidden commands, so help stays clean.
	root.AddCommand(
		hiddenAlias("assess", newAssessCmd()),
		hiddenAlias("discover", newDiscoverCmd()),
		hiddenAlias("scan", newScanCmd()),
		hiddenAlias("enumerate", newEnumerateCmd()),
		hiddenAlias("observe", newObserveCmd()),
		hiddenAlias("analyze", newAnalyzeCmd()),
		hiddenAlias("findings", newFindingsCmd()),
		hiddenAlias("evidence", newEvidenceCmd()),
		hiddenAlias("target", newTargetCmd()),
		hiddenAlias("session", newSessionCmd()),
		hiddenAlias("events", newEventsCmd()),
		hiddenAlias("capture", newCaptureCmd()),
		hiddenAlias("credentials", newCredentialsCmd()),
		hiddenAlias("bluetooth", newBluetoothCmd()),
		hiddenAlias("validate", newOperationCmd(models.ClassValidation)),
		hiddenAlias("test", newOperationCmd(models.ClassActiveTest)),
	)
	return root
}

// hiddenAlias registers a command under its bare name, hidden from help, so
// the pre-tier invocation form keeps resolving. The trailing usage breadcrumb
// (e.g. "target usb [serial]") is preserved.
func hiddenAlias(name string, cmd *cobra.Command) *cobra.Command {
	if old := cmd.Name(); name != old {
		cmd.Use = name + cmd.Use[len(old):]
	}
	cmd.Hidden = true
	return cmd
}

func appInitErr() error {
	if appState == nil {
		return nil
	}
	return appState.InitErr
}

// ctxOf returns the command's context.
func ctxOf(cmd *cobra.Command) context.Context {
	if cmd.Context() != nil {
		return cmd.Context()
	}
	return context.Background()
}

// authorizedFrom returns whether --authorized/-y was explicitly passed.
func authorizedFrom(cmd *cobra.Command) bool {
	f := cmd.Flags().Lookup("authorized")
	return f != nil && f.Changed && f.Value.String() == "true"
}
