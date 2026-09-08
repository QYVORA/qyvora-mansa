// Package mansa cli wires the mansa command tree, shared flags, exit-code
// handling, and cancellation. Execute never calls os.Exit; callers control
// process termination.
package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/QYVORA/qyvora-mansa/internal/app"
	"github.com/QYVORA/qyvora-mansa/internal/console"
	errs "github.com/QYVORA/qyvora-mansa/internal/errors"
	"github.com/QYVORA/qyvora-mansa/internal/exitcode"
	"github.com/QYVORA/qyvora-mansa/internal/version"
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

// consoleExitCode carries the console's exit code into ExecuteArgs.
var consoleExitCode int

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
	formatFlag  string
	eventsFlag  string
	quietFlag   bool
	verboseFlag bool
	dryRunFlag  bool
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "mansa",
		Short: "Authorized wireless security assessment framework",
		Long: `mansa is a terminal-first wireless security assessment framework.

Run it with no arguments to enter the interactive console, or use the
same commands one-shot: mansa scan --sim, mansa analyze --session ... .
 
It performs authorized wireless discovery, access-point enumeration,
client observation, WLAN security analysis, channel/RF analysis, and
produces evidence-backed findings with transparent risk scoring.

Authorized use only: assess wireless networks you own or are authorized
to evaluate.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.Version,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			if initErr := appInitErr(); initErr != nil {
				return errs.NewExitError(2, initErr.Error())
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
			if formatFlag == "json" || eventsFlag != "" || quietFlag {
				return cmd.Help()
			}
			consoleExitCode = console.New(console.Options{
				Interactive: term.IsTerminal(int(os.Stdin.Fd())),
				Out:         cmd.OutOrStdout(),
				Err:         cmd.ErrOrStderr(),
				App:         appState,
			}).Run(cmd.Context())
			return nil
		},
	}
	pf := root.PersistentFlags()
	pf.StringVarP(&formatFlag, "output", "o", "", "output format: terminal, json, yaml, markdown, html")
	pf.BoolVar(&quietFlag, "quiet", false, "suppress non-error output")
	pf.BoolVarP(&verboseFlag, "verbose", "v", false, "verbose output")
	pf.StringVar(&eventsFlag, "events", "", "emit JSONL event stream to stdout, stderr, or a file path")
	pf.BoolVar(&dryRunFlag, "dry-run", false, "show the assessment plan without executing")
	pf.BoolP("authorized", "y", false, "confirm authorization scope non-interactively")

	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return usageError{err}
	})
	root.SetVersionTemplate(fmt.Sprintf("mansa %s\n", version.Version))

	root.AddCommand(newVersionCmd())
	root.AddCommand(newCapabilitiesCmd())
	root.AddCommand(newCompletionCmd())
	root.AddCommand(newUpdatesCmd())
	root.AddCommand(newAssessCmd())
	root.AddCommand(newDiscoverCmd())
	root.AddCommand(newScanCmd())
	root.AddCommand(newEnumerateCmd())
	root.AddCommand(newObserveCmd())
	root.AddCommand(newAnalyzeCmd())
	root.AddCommand(newFindingsCmd())
	root.AddCommand(newEvidenceCmd())
	root.AddCommand(newReportCmd())
	root.AddCommand(newTargetCmd())
	root.AddCommand(newSessionCmd())
	root.AddCommand(newEventsCmd())
	return root
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
