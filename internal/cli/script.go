package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-script/ast"
	"github.com/QYVORA/qyvora-script/binding"
	"github.com/QYVORA/qyvora-script/interpreter"
	"github.com/QYVORA/qyvora-script/parser"

	"github.com/QYVORA/qyvora-mansa/internal/app"
	"github.com/QYVORA/qyvora-mansa/internal/capabilities"
	"github.com/QYVORA/qyvora-mansa/internal/pipeline"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// newScriptCmd adds the flat `script` utility that runs the shared
// qyvora-script engine (ARCH-004 Part C). `script run <file>` executes a
// script; `script build <file>` prints a dry-run plan. A bare `script <file>`
// runs the file for convenience.
func newScriptCmd() *cobra.Command {
	run := func(dryRun bool) func(*cobra.Command, []string) error {
		return func(cmd *cobra.Command, args []string) error {
			return runScriptFile(cmd, args[0], dryRun)
		}
	}
	cmd := &cobra.Command{
		Use:   "script <file>",
		Short: "run a .qs script with the shared scripting engine",
		Args:  cobra.ExactArgs(1),
		RunE:  run(false),
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "run <file>",
			Short: "execute a script file",
			Args:  cobra.ExactArgs(1),
			RunE:  run(false),
		},
		&cobra.Command{
			Use:   "build <file>",
			Short: "validate a script file and print a dry-run plan",
			Args:  cobra.ExactArgs(1),
			RunE:  run(true),
		},
	)
	return cmd
}

// runScriptFile parses (build) or executes (run) a script against mansa's
// binding.
func runScriptFile(cmd *cobra.Command, path string, dryRun bool) error {
	src, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading script: %w", err)
	}
	prog, err := parser.Parse(string(src))
	if err != nil {
		return usagef("%s", err.Error())
	}
	if dryRun {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "script plan "+path)
		for _, line := range ast.Describe(prog) {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  -", line)
		}
		return nil
	}
	if appState == nil {
		appState = app.New("")
	}
	b := &scriptBinding{
		ctx:   ctxOf(cmd),
		allow: allowShellOut,
		cfg:   map[string]string{},
	}
	engine := interpreter.NewEngine(b)
	engine.Events = os.Stderr
	if err := engine.RunProgram(prog); err != nil {
		return usagef("%s", err.Error())
	}
	return nil
}

// scriptBinding implements binding.Binding against mansa's authorized wireless
// assessment pipeline. Modules map to pipeline stages: "mansa.discover" runs
// up to and including discovery, "mansa.observe" through observation, and
// "assess" runs the whole pipeline.
type scriptBinding struct {
	ctx   context.Context
	allow bool
	cfg   map[string]string
	last  *models.Session
}

var _ binding.Binding = (*scriptBinding)(nil)

// Capabilities lists the capability IDs this binding accepts: the tool's
// machine contract plus the whole-pipeline "assess" entry.
func (b *scriptBinding) Capabilities() []string {
	registry := capabilities.Registry()
	ids := make([]string, 0, 1+len(registry))
	ids = append(ids, "assess")
	for _, t := range registry {
		ids = append(ids, t.ID)
	}
	return ids
}

// AllowShellOut reports whether exec/run.cmd may run: only with the explicit
// flag or the shared opt-in environment variable.
func (b *scriptBinding) AllowShellOut() bool { return b.allow || shellOutEnv() }

func shellOutEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(interpreter.AllowShellOutEnv))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// Call dispatches one engine capability invocation.
func (b *scriptBinding) Call(capabilityID string, args []binding.Value) (binding.Value, error) {
	switch capabilityID {
	case binding.CapEcho:
		_, _ = fmt.Fprintln(os.Stdout, asStr(args, 0))
		return nil, nil

	case binding.CapSetConfig:
		b.cfg[asStr(args, 0)] = asStr(args, 1)
		return nil, nil

	case binding.CapGetConfig:
		return b.cfg[asStr(args, 0)], nil

	case binding.CapStart:
		return nil, b.start(asStr(args, 0))

	case binding.CapStop, binding.CapIsRunning:
		if capabilityID == binding.CapIsRunning {
			return false, nil
		}
		return nil, nil

	case binding.CapShow:
		return nil, b.show(asStr(args, 0))

	case binding.CapReport:
		return nil, b.report(asStr(args, 0))

	case binding.CapProp:
		return b.prop(asStr(args, 0)), nil

	case binding.CapExec:
		return nil, b.exec(asStr(args, 0))
	}
	return nil, fmt.Errorf("unknown capability %q", capabilityID)
}

// start runs the pipeline stage associated with a module id.
func (b *scriptBinding) start(id string) error {
	if id == "mansa.capture.live" {
		return fmt.Errorf("live capture is not implemented; " +
			"refused (use the offline simulation or a capture file)")
	}
	stage := ""
	switch id {
	case "assess", "mansa.assess", "":
		// whole pipeline
	case "mansa.discover":
		stage = pipeline.StageDiscover
	case "mansa.scan", "mansa.enumerate":
		stage = pipeline.StageEnumerate
	case "mansa.observe":
		stage = pipeline.StageObserve
	default:
		if !hasCapability(id) {
			return fmt.Errorf("unknown module %q", id)
		}
		// A capability without a discrete stage runs the whole pipeline that
		// covers it.
	}
	return b.run(stage)
}

// run resolves a target, runs the pipeline (or one stage), and captures the
// session for $(...) interpolation.
func (b *scriptBinding) run(stage string) error {
	if appState == nil {
		return fmt.Errorf("mansa is not initialized")
	}
	sim := true
	if v, ok := b.cfg["assess.sim"]; ok {
		sim = isTrue(v)
	} else if v, ok := b.cfg["sim"]; ok {
		sim = isTrue(v)
	}
	iface := b.cfg["assess.interface"]
	if iface == "" {
		iface = b.cfg["interface"]
	}
	ssid := b.cfg["assess.ssid"]
	bssid := b.cfg["assess.bssid"]
	t, err := appState.EstablishTarget(sim, iface, ssid, bssid)
	if err != nil {
		return fmt.Errorf("target error: %w", err)
	}
	if !sim {
		if _, err := appState.Authorize(t, isTrue(b.cfg["assess.authorized"])); err != nil {
			return err
		}
	}
	var sess *models.Session
	if stage == "" {
		sess, err = appState.RunPipeline(b.ctx, t, sim)
	} else {
		sess, err = appState.RunPipelineStage(b.ctx, t, sim, stage)
	}
	if err != nil {
		return err
	}
	b.last = sess
	if sess != nil {
		b.print(sess)
	}
	return nil
}

// print renders the session summary in the active output format.
func (b *scriptBinding) print(sess *models.Session) {
	if appState.Printer.Format() != "terminal" {
		appState.Printer.Print(sess)
		return
	}
	out := appState.Printer.Writer()
	fmt.Fprintf(out, "Session %s (%s)\n", sess.ID, sess.Target)
	fmt.Fprintf(out, "  Access points: %d\n", len(sess.AccessPoints))
	fmt.Fprintf(out, "  Stations:      %d\n", len(sess.Stations))
	fmt.Fprintf(out, "  Findings:      %d\n", len(sess.Findings))
	fmt.Fprintf(out, "  Risk:          %d/100 (%s)\n", sess.RiskScore, sess.RiskLevel)
}

// show prints metadata for a module/capability id.
func (b *scriptBinding) show(id string) error {
	rows := [][]string{}
	if id == "assess" || id == "" {
		rows = append(rows, []string{"assess", "run the full wireless assessment pipeline"})
	}
	for _, t := range capabilities.Registry() {
		if id == "" || t.ID == id {
			rows = append(rows, []string{t.ID, t.Name, string(t.Risk)})
		}
	}
	if len(rows) == 0 {
		return fmt.Errorf("unknown module %q", id)
	}
	appState.Printer.PrintTable([]string{"capability", "name", "risk"}, rows)
	return nil
}

// report writes a JSON session report for the most recent run.
func (b *scriptBinding) report(path string) error {
	if b.last == nil {
		return fmt.Errorf("no assessment to report; run a module first")
	}
	if path == "" {
		path = "mansa-report.json"
	}
	data, err := json.MarshalIndent(b.last, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(appState.Printer.Writer(), "report written to "+path)
	return nil
}

// prop resolves live properties for $(...) interpolation from the last run.
func (b *scriptBinding) prop(name string) binding.Value {
	s := b.last
	if s == nil {
		return nil
	}
	switch name {
	case "session.id", "result.id":
		return s.ID
	case "session.target", "result.target":
		return s.Target
	case "result.interface":
		return s.Interface
	case "result.offline":
		return boolWord(s.Offline)
	case "result.access_points":
		return fmt.Sprintf("%d", len(s.AccessPoints))
	case "result.stations":
		return fmt.Sprintf("%d", len(s.Stations))
	case "result.interfaces":
		return fmt.Sprintf("%d", len(s.Interfaces))
	case "result.bluetooth":
		return fmt.Sprintf("%d", len(s.BluetoothDevices))
	case "result.findings":
		return fmt.Sprintf("%d", len(s.Findings))
	case "result.evidence":
		return fmt.Sprintf("%d", len(s.Evidence))
	case "result.risk_score":
		return fmt.Sprintf("%d", s.RiskScore)
	case "result.risk_level":
		return s.RiskLevel
	}
	return nil
}

// exec runs a one-shot mansa command line. The interpreter only reaches here
// after AllowShellOut reported true.
func (b *scriptBinding) exec(line string) error {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	code := ExecuteArgs(b.ctx, strings.Fields(line))
	if code != 0 {
		return fmt.Errorf("command exited with code %d", code)
	}
	return nil
}

// hasCapability reports whether id is a registered mansa capability.
func hasCapability(id string) bool {
	for _, t := range capabilities.Registry() {
		if t.ID == id {
			return true
		}
	}
	return false
}

func asStr(args []binding.Value, i int) string {
	if i >= len(args) || args[i] == nil {
		return ""
	}
	if s, ok := args[i].(string); ok {
		return s
	}
	return fmt.Sprintf("%v", args[i])
}

func isTrue(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func boolWord(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
