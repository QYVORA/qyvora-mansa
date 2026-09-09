// Package app implements the Mansa application service layer shared by
// the one-shot CLI and the interactive console. Both surfaces invoke
// the same functions; there is no duplicated business logic.
package app

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/QYVORA/qyvora-mansa/internal/capabilities"
	"github.com/QYVORA/qyvora-mansa/internal/config"
	"github.com/QYVORA/qyvora-mansa/internal/events"
	"github.com/QYVORA/qyvora-mansa/internal/logger"
	"github.com/QYVORA/qyvora-mansa/internal/output"
	"github.com/QYVORA/qyvora-mansa/internal/pipeline"
	"github.com/QYVORA/qyvora-mansa/internal/reporting"
	"github.com/QYVORA/qyvora-mansa/internal/session"
	"github.com/QYVORA/qyvora-mansa/internal/target"
	"github.com/QYVORA/qyvora-mansa/internal/transport"
	"github.com/QYVORA/qyvora-mansa/internal/version"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// AppState holds all shared Mansa application state.
type AppState struct {
	Cfg       *viper.Viper
	Log       *logger.Logger
	Printer   *output.Printer
	Store     *session.Store
	Targets   *target.Manager
	Events    *events.Stream
	Backend   transport.Backend
	InitErr   error
	Verbose   bool
	Quiet     bool
	OutputFmt string
	EventsF   string
	DryRun    bool
}

// New creates an AppState from the current environment.
func New(cfgFile string) *AppState {
	a := &AppState{}
	v, err := config.Load(cfgFile)
	if err != nil {
		a.InitErr = err
		return a
	}
	a.Cfg = v
	a.Log = logger.New()
	a.Log.SetLevel(logger.ParseLevel(v.GetString("log.level")))
	a.Printer = output.New()
	a.Store = session.NewStore(v.GetString("session.dir"))
	a.Targets = target.NewManager(v.GetString("target.state"))
	return a
}

// Init initializes deferred components after CLI flags are parsed.
func (a *AppState) Init(formatFlag, eventsFlag string, quiet, verbose, dryRun bool) {
	a.Verbose = verbose
	a.Quiet = quiet
	a.DryRun = dryRun
	a.Log.SetVerbose(verbose)
	a.Log.SetQuiet(quiet)
	a.EventsF = eventsFlag
	a.OutputFmt = formatFlag
	a.resolvePrinter()
	a.resolveBackend()
	if eventsFlag != "" {
		a.resolveEvents()
	}
}

func (a *AppState) resolvePrinter() {
	format := "terminal"
	switch {
	case a.OutputFmt != "":
		format = a.OutputFmt
	case a.Cfg.GetBool("json"):
		format = "json"
	case a.Cfg.IsSet("output"):
		if v, ok := a.Cfg.Get("output").(string); ok && v != "" {
			format = v
		}
	}
	f, err := output.ParseFormat(format)
	if err != nil {
		a.InitErr = err
		return
	}
	a.Printer.SetFormat(f)
}

func (a *AppState) resolveBackend() {
	linux := transport.NewLinux()
	if linux.Supported() {
		a.Backend = linux
		return
	}
	a.Backend = transport.New() // simulation fallback
}

func (a *AppState) resolveEvents() {
	sink, err := a.resolveEventSink()
	if err != nil {
		a.InitErr = err
		return
	}
	a.Events = events.NewStream(sink)
}

func (a *AppState) resolveEventSink() (*os.File, error) {
	switch strings.ToLower(a.EventsF) {
	case "", "off":
		return nil, nil
	case "stdout":
		return os.Stdout, nil
	case "stderr":
		return os.Stderr, nil
	default:
		return os.OpenFile(a.EventsF, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	}
}

// EstablishTarget resolves a target from flags/simulation for a pipeline run.
func (a *AppState) EstablishTarget(sim bool, iface, _ string, _ string) (*models.Target, error) {
	if sim {
		t := &models.Target{
			Type:      models.TargetInterface,
			Value:     "simulation",
			Interface: "wlan0",
			Authorization: models.Authorization{
				Granted:   true,
				GrantedAt: time.Now().UTC(),
				Scope:     "offline simulation dataset only; no live wireless I/O",
				Method:    "demo",
			},
			CreatedAt: time.Now().UTC(),
		}
		t.ID = models.NewID("tgt")
		_ = a.Targets.Set(t)
		a.Backend = transport.New()
		return t, nil
	}
	if iface == "" {
		iface = a.Cfg.GetString("wireless.interface")
	}
	t := &models.Target{
		Type:      models.TargetInterface,
		Value:     iface,
		Interface: iface,
		CreatedAt: time.Now().UTC(),
	}
	t.ID = models.NewID("tgt")
	return t, nil
}

// Authorize performs the authorization gate.
func (a *AppState) Authorize(t *models.Target, forceAuth bool) (*models.Target, error) {
	if t.Authorized() {
		return t, nil
	}
	if forceAuth || strings.EqualFold(os.Getenv("QYVORA_AUTHORIZED"), "true") || a.Cfg.GetBool("authorized") {
		t.Authorization = models.Authorization{
			Granted:   true,
			GrantedAt: time.Now().UTC(),
			Scope:     "authorized wireless security assessment",
			Method:    "cli",
			GrantedBy: currentUser(),
		}
		return t, nil
	}
	if isTTY(os.Stdin) {
		fmt.Fprintf(os.Stderr, "\n  Authorized wireless security assessment\n")
		fmt.Fprintf(os.Stderr, "  Target: %s\n\n", t.DisplayName())
		fmt.Fprintf(os.Stderr, "  Confirm authorization? [y/N] ")
		var ans string
		_, _ = fmt.Scanln(&ans)
		if strings.ToLower(strings.TrimSpace(ans)) == "y" {
			t.Authorization = models.Authorization{
				Granted:   true,
				GrantedAt: time.Now().UTC(),
				Scope:     "authorized wireless security assessment",
				Method:    "interactive",
				GrantedBy: currentUser(),
			}
			return t, nil
		}
		return t, fmt.Errorf("authorization declined")
	}
	return t, fmt.Errorf("target authorization required; re-run with --authorized to confirm scope non-interactively")
}

// RunPipeline executes the assessment pipeline.
func (a *AppState) RunPipeline(ctx context.Context, t *models.Target, sim bool) (*models.Session, error) {
	if a.DryRun {
		a.printDryRunPlan(t, sim)
		return nil, nil
	}
	sess := models.NewSession(t)
	sess.Offline = sim
	if sim {
		a.Backend = transport.New()
	} else {
		a.resolveBackend()
	}
	env := &pipeline.Env{
		Backend:  a.Backend,
		Session:  sess,
		Events:   a.Events,
		Offline:  sim,
		ReportFn: a.writeReport,
	}
	runner := &pipeline.Runner{}
	if err := runner.Run(ctx, env); err != nil {
		return sess, fmt.Errorf("pipeline failed: %w", err)
	}
	path, err := a.Store.Save(sess)
	if err != nil {
		a.Log.Warnf("failed to persist session: %v", err)
	}
	if path != "" {
		a.Log.Infof("session saved: %s", path)
	}
	return sess, nil
}

// RunPipelineStage runs the pipeline up to (and including) a single stage.
func (a *AppState) RunPipelineStage(ctx context.Context, t *models.Target, sim bool, stage string) (*models.Session, error) {
	if a.DryRun {
		a.printDryRunPlan(t, sim)
		return nil, nil
	}
	sess := models.NewSession(t)
	sess.Offline = sim
	if sim {
		a.Backend = transport.New()
	} else {
		a.resolveBackend()
	}
	env := &pipeline.Env{
		Backend:  a.Backend,
		Session:  sess,
		Events:   a.Events,
		Offline:  sim,
		ReportFn: a.writeReport,
	}
	runner := &pipeline.Runner{}
	if err := runner.RunUntil(ctx, env, stage); err != nil {
		return sess, fmt.Errorf("pipeline failed: %w", err)
	}
	_, _ = a.Store.Save(sess)
	return sess, nil
}

func (a *AppState) printDryRunPlan(t *models.Target, sim bool) {
	// The plan is informational, not machine output: route it to err output
	// when a machine-readable format is active so stdout stays pure.
	w := a.Printer.Writer()
	if a.Printer.Format() != output.FormatTerminal {
		w = os.Stderr
	}
	fmt.Fprintf(w, "Dry run plan:\n")
	fmt.Fprintf(w, "  Target:       %s\n", t.DisplayName())
	fmt.Fprintf(w, "  Interface:    %s\n", t.Interface)
	fmt.Fprintf(w, "  Simulation:   %v\n", sim)
	fmt.Fprintf(w, "  Stages:       %s\n", strings.Join(pipeline.StageOrder, " → "))
	fmt.Fprintf(w, "  Backend:      %s\n", a.Backend.Name())
}

func (a *AppState) writeReport(_ context.Context, sess *models.Session) error {
	dir := a.Cfg.GetString("report.dir")
	if dir == "" {
		dir = "reports"
	}
	_ = os.MkdirAll(dir, 0o700)
	format := a.Cfg.GetString("report.format")
	if format == "" {
		format = "terminal"
	}
	f, err := reporting.ParseFormat(format)
	if err != nil {
		f = reporting.FormatTerminal
	}
	content, err := reporting.Render(sess, f)
	if err != nil {
		return err
	}
	path := dir + "/report." + string(f)
	return os.WriteFile(path, []byte(content), 0o600)
}

// AnalyzeSession re-runs the analysis pass (rules, validation, risk) on an
// existing session loaded from disk, then persists it.
func (a *AppState) AnalyzeSession(ctx context.Context, sess *models.Session) (*models.Session, error) {
	env := &pipeline.Env{Backend: a.Backend, Session: sess, Events: a.Events}
	r := &pipeline.Runner{}
	if err := r.RunStages(ctx, env, []string{pipeline.StageAnalyze, pipeline.StageValidate}); err != nil {
		return sess, err
	}
	sess.Stages = append(sess.Stages, pipeline.StageFindings, pipeline.StageRisk)
	sess.RiskScore = models.AggregateRisk(sess.Findings)
	sess.RiskLevel = string(models.LevelFromScore(sess.RiskScore))
	sess.Finish()
	if _, err := a.Store.Save(sess); err != nil {
		a.Log.Warnf("failed to persist analyzed session: %v", err)
	}
	return sess, nil
}

// LatestSession loads the most recent session.
func (a *AppState) LatestSession() (*models.Session, error) {
	return a.Store.Latest()
}

// LoadSession loads a session by ID or "latest".
func (a *AppState) LoadSession(id string) (*models.Session, error) {
	if id == "" || id == "latest" {
		return a.LatestSession()
	}
	return a.Store.Load(id)
}

// Capabilities returns the machine-readable capability list.
func (a *AppState) Capabilities() []capabilities.Tool {
	return capabilities.Registry()
}

// VersionInfo returns the formatted version string.
func (a *AppState) VersionInfo() string {
	return version.String()
}

// VersionJSON returns a machine-readable version object.
func (a *AppState) VersionJSON() map[string]string {
	return map[string]string{
		"framework": "mansa",
		"version":   version.Version,
		"commit":    version.Commit,
		"date":      version.Date,
	}
}

func currentUser() string {
	u, err := user.Current()
	if err != nil {
		return "unknown"
	}
	return u.Username
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
