package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-mansa/internal/active"
	errs "github.com/QYVORA/qyvora-mansa/internal/errors"
	"github.com/QYVORA/qyvora-mansa/internal/exitcode"
	"github.com/QYVORA/qyvora-mansa/internal/exploitation"
	"github.com/QYVORA/qyvora-mansa/internal/operation"
	"github.com/QYVORA/qyvora-mansa/internal/transport"
	"github.com/QYVORA/qyvora-mansa/internal/wireless"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// newOperationCmds returns the three operation-class commands.
//
// Class is a property of the module, not of the command: each of these resolves
// modules and refuses any whose declared class is not the one it runs. That is
// what keeps `mansa exploit` from running a validation module, which would apply
// the exploit gates to it while the validation gates applied to nothing.
func newOperationCmds() []*cobra.Command {
	return []*cobra.Command{
		newOperationCmd(models.ClassValidation),
		newOperationCmd(models.ClassActiveTest),
		newOperationCmd(models.ClassExploitation),
	}
}

// operationVerb is the command name for a class.
func operationVerb(class models.OperationClass) string {
	switch class {
	case models.ClassValidation:
		return "validate"
	case models.ClassActiveTest:
		return "test"
	case models.ClassExploitation:
		return "exploit"
	default:
		return string(class)
	}
}

// newOperationCmd builds one class's command with its `list` subcommand.
func newOperationCmd(class models.OperationClass) *cobra.Command {
	verb := operationVerb(class)
	cmd := &cobra.Command{
		Use:   verb,
		Short: operationShort(class),
		Long:  operationLong(class),
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return usagef("a module id is required; run 'mansa %s list' to see the modules in this class", verb)
			}
			if len(args) > 1 {
				return usagef("expected one module id, got %d arguments", len(args))
			}
			return runOperation(cmd, args[0], class)
		},
	}
	cmd.AddCommand(newOperationListCmd(class))
	bindOperationFlags(cmd)
	return cmd
}

// newOperationListCmd prints one class's modules from the registry.
//
// The list is the registry itself rather than a second copy of it, so a module
// cannot be published in one surface and missing from another.
func newOperationListCmd(class models.OperationClass) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the modules in this class",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			metas := operationRegistry().ByClass(class)
			if len(metas) == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "no %s modules are registered\n", class)
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%-38s %-7s %-6s %s\n", "MODULE", "RISK", "SIM", "TITLE")
			for _, meta := range metas {
				sim := "no"
				if meta.SimulationAvailable {
					sim = "yes"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%-38s %-7s %-6s %s\n", meta.ID, meta.Risk, sim, meta.Title)
			}
			return nil
		},
	}
}

// bindOperationFlags declares the flags every operation run accepts.
func bindOperationFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.String("target", "", "authorized target: a stored target id, a literal address or name, or 'auto' for the interface")
	flags.String("interface", "", "wireless interface the operation uses")
	flags.String("session", "", "session supplying collected observations, or 'latest'")
	flags.String("database", "", "saved GATT attribute table JSON")
	flags.String("operator", "", "identity recorded as responsible for the run")
	flags.StringArray("param", nil, "module parameter as name=value; a bare --param name acknowledges a flag-style parameter")
	flags.Bool("sim", false, "run the simulation path; no over-air action is taken")
	flags.Bool("dry-run", false, "print the plan without transmitting or collecting")
}

// operationRegistry returns the single module registry every surface reads.
//
// It is the same construction the capability contract uses, so the published
// contract and the CLI list cannot disagree about what exists.
func operationRegistry() *operation.Registry {
	registry := operation.NewRegistry()
	registry.MustRegister(active.BluetoothModules()...)
	registry.MustRegister(active.WiFiModules()...)
	exploitation.NewRegistry(registry).MustRegister(exploitation.Builtins()...)
	return registry
}

// runOperation resolves, gates, and runs one module.
func runOperation(cmd *cobra.Command, moduleID string, class models.OperationClass) error {
	flags := cmd.Flags()
	targetFlag, _ := flags.GetString("target")
	iface, _ := flags.GetString("interface")
	sessionFlag, _ := flags.GetString("session")
	database, _ := flags.GetString("database")
	operator, _ := flags.GetString("operator")
	rawParams, _ := flags.GetStringArray("param")
	simulated, _ := flags.GetBool("sim")
	dryRun, _ := flags.GetBool("dry-run")

	params, err := parseOperationParams(rawParams)
	if err != nil {
		return err
	}

	registry := operationRegistry()
	module, ok := registry.Get(moduleID)
	if !ok {
		// An unknown id lists what does exist. A typo that reported only "not
		// found" would leave the caller guessing which of eight modules they
		// meant.
		return usagef("no module named %q in this class; run 'mansa %s list'", moduleID, operationVerb(class))
	}
	meta := module.Meta()
	if meta.Class != class {
		return usagef("%s is a %s module; run it with 'mansa %s'", meta.ID, meta.Class, operationVerb(meta.Class))
	}

	session, err := resolveOperationSession(sessionFlag)
	if err != nil {
		return err
	}

	target, err := resolveOperationTarget(cmd, targetFlag, iface, simulated)
	if err != nil {
		return err
	}

	executor := &operation.Executor{
		Registry: registry,
		Backend:  operationBackend(simulated),
		Events:   appState.Events,
	}
	record, runErr := executor.Execute(cmd.Context(), operation.Request{
		ModuleID:  moduleID,
		Class:     class,
		Target:    target,
		Interface: iface,
		Session:   session,
		Params:    params,
		Operator:  operator,
		Simulated: simulated,
		DryRun:    dryRun,
		Database:  database,
	})

	// The record is reported even when the run was refused: a refusal that left
	// no record is indistinguishable from a command that never ran.
	if session != nil {
		session.AddOperation(record)
		if _, saveErr := appState.Store.Save(session); saveErr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not save the session record: %v\n", saveErr)
		}
	}
	printOperationRecord(cmd, record)
	if runErr != nil {
		return runErr
	}
	if record.Status != models.StatusCompleted && record.Status != models.StatusPlanned {
		return errs.NewExitError(exitcode.Runtime, "operation did not complete: "+string(record.Status))
	}
	return nil
}

// operationBackend picks the provider for a run.
//
// A simulated run always uses the fixture provider, so `--sim` cannot reach
// hardware even on a host that has it.
func operationBackend(simulated bool) transport.Backend {
	if simulated {
		return transport.New()
	}
	if appState != nil && appState.Backend != nil {
		return appState.Backend
	}
	return transport.NewLinux()
}

// resolveOperationTarget resolves the authorized scope for a run.
//
// A simulation target is authorized in the fixture, so a simulated run is not
// stopped by the authorization gate it cannot meaningfully satisfy.
func resolveOperationTarget(cmd *cobra.Command, targetFlag, iface string, simulated bool) (*models.Target, error) {
	switch {
	case targetFlag == "" || strings.EqualFold(targetFlag, "auto"):
		return appState.EstablishTarget(simulated, iface, "", "")
	case simulated:
		// A simulated run still needs a named scope so the record says what was
		// simulated, but it does not need a stored or literal target.
		//
		// The type is inferred from the value rather than assumed to be an
		// interface: a Bluetooth adapter module run against --target hci0 would
		// otherwise be refused on scope for naming an interface that has nothing
		// to do with the question being asked.
		return &models.Target{
			ID: models.NewID("tgt"), Type: inferTargetType(targetFlag), Value: targetFlag,
			Interface: iface,
			Authorization: models.Authorization{
				Granted: true, GrantedAt: time.Now().UTC(),
				Scope: "offline simulation dataset only; no live wireless I/O", Method: "sim",
			},
			CreatedAt: time.Now().UTC(),
		}, nil
	}
	// A stored target id resolves first so a run can reuse a scope that was
	// authorized earlier.
	if stored, ok := appState.Targets.Get(targetFlag); ok {
		return appState.Authorize(stored, authorizedFrom(cmd))
	}
	// Otherwise the value is taken as a literal target. Its scope is inferred
	// from the value itself rather than asked for, because a MAC address names a
	// BSSID and a name names an SSID. The module's own declared target types
	// are checked later by the executor, so a wrong guess is refused there with
	// the module's reason rather than guessed at here.
	return appState.Authorize(literalTarget(targetFlag, iface), authorizedFrom(cmd))
}

// literalTarget builds a target from a literal address or name.
func literalTarget(value, iface string) *models.Target {
	value = strings.TrimSpace(value)
	return &models.Target{
		ID: models.NewID("tgt"), Type: inferTargetType(value),
		Value: value, Interface: iface, CreatedAt: time.Now().UTC(),
	}
}

// inferTargetType reads the scope out of the value itself.
//
// A MAC address names a BSSID, an HCI node names a Bluetooth adapter, and
// anything else is treated as a name. The module's declared target types are
// checked later by the executor, so this is a guess that gets refused with the
// module's own reason rather than a silent reinterpretation.
func inferTargetType(value string) models.TargetType {
	value = strings.TrimSpace(value)
	if _, err := wireless.ParseMACAddress(value); err == nil {
		return models.TargetBSSID
	}
	if isHCIName(value) {
		return models.TargetBluetoothAdapter
	}
	return models.TargetSSID
}

// isHCIName reports whether a value names a Bluetooth HCI adapter, which Linux
// spells hci0, hci1, and so on.
func isHCIName(value string) bool {
	rest, found := strings.CutPrefix(strings.ToLower(value), "hci")
	if !found || rest == "" {
		return false
	}
	for _, r := range rest {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// resolveOperationSession loads the session a run reads from and records to.
func resolveOperationSession(sessionFlag string) (*models.Session, error) {
	switch {
	case sessionFlag == "":
		return nil, nil
	case strings.EqualFold(sessionFlag, "latest"):
		return appState.LatestSession()
	default:
		return appState.LoadSession(sessionFlag)
	}
}

// parseOperationParams turns repeated --param flags into the request map.
//
// A bare --param name is kept as present-but-empty, because the executor reads
// a valueless flag-style parameter as an acknowledgement: the operator naming it
// is the whole point. A repeated name is refused, because two values for one
// parameter means the operator's intent is ambiguous.
func parseOperationParams(entries []string) (map[string]string, error) {
	params := map[string]string{}
	for _, entry := range entries {
		name, value, found := strings.Cut(entry, "=")
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, usagef("--param needs a name, for example --param station=11:22:33:44:55:66")
		}
		if _, exists := params[name]; exists {
			return nil, usagef("--param %s was supplied more than once", name)
		}
		if !found {
			params[name] = ""
			continue
		}
		params[name] = value
	}
	return params, nil
}

// printOperationRecord renders a finished run.
func printOperationRecord(cmd *cobra.Command, record models.OperationRecord) {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "%s\n", record.Status)
	if record.ModuleID != "" {
		fmt.Fprintf(out, "  module:  %s\n", record.ModuleID)
	}
	if record.Target != "" {
		fmt.Fprintf(out, "  target:  %s (%s)\n", record.Target, record.TargetType)
	}
	if record.Interface != "" {
		fmt.Fprintf(out, "  iface:   %s\n", record.Interface)
	}
	if record.Simulated {
		fmt.Fprintf(out, "  mode:    simulation; no over-air action was taken\n")
	}
	if record.FramesTransmitted > 0 || record.BytesTransmitted > 0 {
		fmt.Fprintf(out, "  frames:  %d accepted, %d bytes; delivery is not established by an accepted write\n",
			record.FramesTransmitted, record.BytesTransmitted)
	}
	if record.CleanupState != "" {
		fmt.Fprintf(out, "  cleanup: %s\n", record.CleanupState)
	}
	for _, note := range record.Notes {
		fmt.Fprintf(out, "  note:    %s\n", note)
	}
	if len(record.Findings) > 0 {
		fmt.Fprintf(out, "  findings: %d\n", len(record.Findings))
		for _, finding := range record.Findings {
			fmt.Fprintf(out, "    %s  %s  [%s/%s]\n", finding.RuleID, finding.Title, finding.Severity, finding.Confidence)
		}
	}
	if len(record.Limitations) > 0 {
		fmt.Fprintf(out, "  limitations:\n")
		for _, limitation := range record.Limitations {
			fmt.Fprintf(out, "    - %s\n", limitation)
		}
	}
	if record.Error != "" {
		fmt.Fprintf(out, "  error:   %s\n", record.Error)
	}
}

// operationShort is the one-line description for a class command.
func operationShort(class models.OperationClass) string {
	switch class {
	case models.ClassValidation:
		return "Run validation modules: confirm or refute an observed condition from collected data"
	case models.ClassActiveTest:
		return "Run active-test modules: transmit a bounded, declared frame set at an authorized target"
	case models.ClassExploitation:
		return "Run exploitation modules: drive an authorized laboratory target toward a known outcome"
	default:
		return string(class)
	}
}

// operationLong is the full help text for a class command.
func operationLong(class models.OperationClass) string {
	var b strings.Builder
	b.WriteString(operationShort(class))
	b.WriteString(".\n\n")
	switch class {
	case models.ClassValidation:
		b.WriteString("Validation modules review data already collected and emit no radio traffic. A run\n")
		b.WriteString("still requires an authorized target so a finding names a scope you are\n")
		b.WriteString("responsible for.\n")
	case models.ClassActiveTest:
		b.WriteString("Every gate runs before any transmission: module resolution, required parameters,\n")
		b.WriteString("target presence, authorization, scope, hardware capability, and simulation\n")
		b.WriteString("availability. --dry-run runs the same gates and transmits nothing, so a plan\n")
		b.WriteString("cannot describe a run that would be refused.\n\n")
		b.WriteString("Frames transmitted is what the kernel accepted. It is never proof that a frame\n")
		b.WriteString("reached the air, and nothing observed in the listen window is a negative result.\n")
	case models.ClassExploitation:
		b.WriteString("This is the highest-risk class: its modules are disruptive or impersonating by\n")
		b.WriteString("definition. Each requires authorization and an explicit --param lab\n")
		b.WriteString("acknowledging that the target is an isolated laboratory you control.\n\n")
		b.WriteString("An exploit reports what it observed and states what that does not prove. A run\n")
		b.WriteString("that observed nothing says so rather than reporting a negative result it cannot\n")
		b.WriteString("support.\n")
	}
	b.WriteString("\nRun 'mansa ")
	b.WriteString(operationVerb(class))
	b.WriteString(" list' to see the modules in this class.")
	return b.String()
}
