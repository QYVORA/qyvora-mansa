package console

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-mansa/internal/pipeline"
	"github.com/QYVORA/qyvora-mansa/internal/reporting"
	"github.com/QYVORA/qyvora-mansa/internal/selfupdate"
	"github.com/QYVORA/qyvora-mansa/internal/version"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// requireLive ensures a non-simulation assessment is authorized.
func (c *Console) requireLive() error {
	if c.sim {
		return nil
	}
	if !c.authorized {
		return fmt.Errorf("live assessment requires authorization; run `authorize` first (or `sim on`)")
	}
	return nil
}

// runPrefersSim returns the simulation override for a single command.
func (c *Console) runPrefersSim(p *Parsed) bool {
	if p.Bool("sim") {
		c.sim = true
	}
	return c.sim
}

func runHelp(c *Console, p *Parsed) error {
	if p.ArgsLen() == 0 {
		c.printf("%s\n", "Mansa console commands")
		lastCat := ""
		for _, cat := range categoryOrder {
			for _, name := range commandNamesIn(cat) {
				cmd := c.cmds[name]
				if cmd.Category != cat {
					_ = lastCat
					continue
				}
				if cmd.Category != lastCat {
					if lastCat != "" {
						c.printf("\n")
					}
					lastCat = cmd.Category
					c.printf("%s\n", c.ui.BoldTeal(cmd.Category))
				}
				c.printf("  %-14s %s\n", cmd.Name, cmd.Summary)
			}
		}
		c.printf("\n%s\n", c.ui.DimWhite("Use 'help <command>' for details. 'exit' leaves the console."))
		return nil
	}
	name := strings.ToLower(p.Arg(0))
	if resolved, ok := c.aliases[name]; ok {
		name = resolved
	}
	cmd, ok := c.cmds[name]
	if !ok {
		return fmt.Errorf("unknown command %q", p.Arg(0))
	}
	c.printf("%s\n\n", c.ui.BoldTeal(strings.ToUpper(cmd.Name)))
	c.printf("  %s\n", cmd.Summary)
	if cmd.Usage != "" {
		c.printf("  Usage: %s\n", cmd.Usage)
	}
	if cmd.Details != "" {
		c.printf("\n  %s\n", cmd.Details)
	}
	return nil
}

func commandNamesIn(cat string) []string {
	var names []string
	for _, cmd := range commandTable() {
		if cmd.Category == cat {
			names = append(names, cmd.Name)
		}
	}
	return names
}

func runVersion(c *Console, _ *Parsed) error {
	c.printf("%s\n", c.app.VersionInfo())
	return nil
}

func runStatus(c *Console, _ *Parsed) error {
	target := "none"
	if c.iface != "" {
		target = c.iface
	}
	mode := "live"
	if c.sim {
		mode = "simulation"
	}
	auth := "no"
	if c.authorized || c.sim {
		auth = "yes"
	}
	backend := c.app.Backend.Name()
	if c.sim {
		backend = "simulation"
	}
	c.ui.KV("interface", target)
	c.ui.KV("mode", mode)
	c.ui.KV("authorized", auth)
	c.ui.KV("backend", backend)
	c.ui.KV("version", c.app.VersionJSON()["version"])
	return nil
}

func runShow(c *Console, p *Parsed) error {
	topic := p.Arg(0)
	if topic == "" {
		return fmt.Errorf("usage: show <interfaces|access-points|aps|stations|clients|observations>")
	}
	sess, err := c.app.LoadSession("")
	if err != nil {
		return fmt.Errorf("no session available: %w", err)
	}
	switch topic {
	case "interfaces":
		if len(sess.Interfaces) == 0 {
			c.printf("  (no interfaces in session)\n")
			return nil
		}
		rows := make([][]string, 0, len(sess.Interfaces))
		for _, iface := range sess.Interfaces {
			rows = append(rows, []string{iface.Name, iface.State, iface.Mode, strings.Join(iface.Supported, ",")})
		}
		c.ui.Table([]string{"interface", "state", "mode", "bands"}, rows)
	case "access-points", "aps", "enumerate":
		c.renderAPs(sess, p)
	case "stations", "clients", "observations":
		if len(sess.Stations) == 0 {
			c.printf("  (no stations observed)\n")
			return nil
		}
		rows := make([][]string, 0, len(sess.Stations))
		for _, st := range sess.Stations {
			rows = append(rows, []string{st.MAC, st.APBSSID, fmt.Sprintf("%d", st.Signal), strings.Join(st.ProbedSSIDs, ",")})
		}
		c.ui.Table([]string{"mac", "ap", "signal", "probed"}, rows)
	default:
		return fmt.Errorf("unknown show topic %q", topic)
	}
	return nil
}

func runUse(c *Console, p *Parsed) error {
	if p.ArgsLen() < 2 {
		return fmt.Errorf("usage: use interface <name>")
	}
	if p.Arg(0) != "interface" {
		return fmt.Errorf("unknown target kind %q (use: interface)", p.Arg(0))
	}
	name := p.Arg(1)
	ifaces, _ := c.app.Backend.DiscoverInterfaces()
	for _, iface := range ifaces {
		if iface.Name == name {
			c.iface = name
			c.ok("using interface %s", name)
			return nil
		}
	}
	return fmt.Errorf("interface %q not found (run `discover` or `show interfaces` to list)", name)
}

func runBack(c *Console, _ *Parsed) error {
	c.iface = ""
	c.authorized = false
	c.ok("interface cleared")
	return nil
}

func runAuthorize(c *Console, _ *Parsed) error {
	if c.iface == "" {
		c.iface = c.app.Cfg.GetString("wireless.interface")
	}
	if c.iface == "" {
		c.iface = "wlan0"
	}
	c.authorized = true
	c.ok("authorization granted for live assessment on %s", c.iface)
	return nil
}

func runSim(c *Console, p *Parsed) error {
	if p.ArgsLen() == 0 || p.Arg(0) == "on" {
		c.sim = true
		c.ok("simulation mode enabled (offline deterministic dataset)")
		return nil
	}
	if p.Arg(0) == "off" {
		c.sim = false
		c.ok("simulation mode disabled")
		return nil
	}
	return fmt.Errorf("usage: sim [on|off]")
}

// runPipeline runs a pipeline up to a stage, sharing the app layer.
func (c *Console) runPipeline(until string, sim bool) (*models.Session, error) {
	iface := c.iface
	if sim && iface == "" {
		iface = "wlan0"
	}
	t := &models.Target{
		Type:      models.TargetInterface,
		Value:     iface,
		Interface: iface,
		CreatedAt: time.Now().UTC(),
	}
	if sim {
		t.Authorization = models.Authorization{
			Granted:   true,
			GrantedAt: time.Now().UTC(),
			Scope:     "offline simulation dataset only",
			Method:    "demo",
		}
	} else if err := c.requireLive(); err != nil {
		return nil, err
	} else {
		t.Authorization = models.Authorization{
			Granted:   true,
			GrantedAt: time.Now().UTC(),
			Scope:     "authorized wireless assessment via console",
			Method:    "console",
		}
	}
	ctx := c.OpContext()
	var sess *models.Session
	var err error
	if until == "" {
		sess, err = c.app.RunPipeline(ctx, t, sim)
	} else {
		sess, err = c.app.RunPipelineStage(ctx, t, sim, until)
	}
	return sess, err
}

func runRun(c *Console, p *Parsed) error {
	sim := c.runPrefersSim(p)
	if c.app.DryRun {
		c.printf("dry-run is enabled; showing plan only.\n")
		return nil
	}
	c.ui.Status("*", "running full assessment pipeline%s", simSuffix(sim))
	c.ui.Status(">", "discover → enumerate → observe → analyze → validate → findings → risk → report")
	sess, err := c.runPipeline("", sim)
	if err != nil {
		_ = sess
		return err
	}
	if sess != nil {
		c.current = &docSession{sessID: sess.ID, summary: summaryOf(sess)}
		c.printSessionSummary(sess)
	}
	return nil
}

func runDiscover(c *Console, p *Parsed) error {
	sim := c.runPrefersSim(p)
	sess, err := c.runPipelineToStage(pipeline.StageEnumerate, sim, false)
	if err != nil {
		return err
	}
	if sess != nil {
		c.current = &docSession{sessID: sess.ID}
		c.ui.Section("Discovered interfaces")
		rows := make([][]string, 0, len(sess.Interfaces))
		for _, iface := range sess.Interfaces {
			rows = append(rows, []string{iface.Name, iface.State, iface.Mode, strings.Join(iface.Supported, ",")})
		}
		c.ui.Table([]string{"interface", "state", "mode", "bands"}, rows)
	}
	return nil
}

func runScan(c *Console, p *Parsed) error {
	sim := c.runPrefersSim(p)
	sess, err := c.runPipelineToStage(pipeline.StageEnumerate, sim, p.Bool("sim"))
	if err != nil {
		return err
	}
	if sess == nil {
		return nil
	}
	c.current = &docSession{sessID: sess.ID}
	c.renderAPs(sess, p)
	return nil
}

func runEnumerate(c *Console, p *Parsed) error {
	sim := c.runPrefersSim(p)
	sess, err := c.runPipelineToStage(pipeline.StageEnumerate, sim, p.Bool("sim"))
	if err != nil {
		return err
	}
	if sess == nil {
		return nil
	}
	c.current = &docSession{sessID: sess.ID}
	c.ui.Section("Access-point inventory")
	c.renderAPs(sess, p)
	return nil
}

func runObserve(c *Console, p *Parsed) error {
	sim := c.runPrefersSim(p)
	sess, err := c.runPipelineToStage(pipeline.StageObserve, sim, p.Bool("sim"))
	if err != nil {
		return err
	}
	if sess == nil {
		return nil
	}
	c.current = &docSession{sessID: sess.ID}
	c.ui.Section("Observed stations")
	if len(sess.Stations) == 0 {
		c.printf("  (no stations observed)\n")
	} else {
		rows := make([][]string, 0, len(sess.Stations))
		for _, st := range sess.Stations {
			rows = append(rows, []string{st.MAC, st.APBSSID, fmt.Sprintf("%d", st.Signal), fmt.Sprintf("%v", st.Associated), strings.Join(st.ProbedSSIDs, ",")})
		}
		c.ui.Table([]string{"mac", "ap", "signal", "associated", "probed"}, rows)
	}
	if len(sess.Traffic) > 0 {
		c.ui.Section("Observed traffic")
		rows := make([][]string, 0, len(sess.Traffic))
		for _, t := range sess.Traffic {
			rows = append(rows, []string{t.Type, t.Protocol, t.Target, t.Detail, fmt.Sprintf("%d", t.Count)})
		}
		c.ui.Table([]string{"type", "protocol", "target", "detail", "count"}, rows)
	}
	return nil
}

// runPipelineToStage runs a pipeline stage with proper sim/dry-run handling.
func (c *Console) runPipelineToStage(stage string, sim, forceSim bool) (*models.Session, error) {
	if forceSim {
		sim = true
	}
	sess, err := c.runPipeline(stage, sim)
	return sess, err
}

func runAnalyze(c *Console, p *Parsed) error {
	id := p.Str("session")
	if id == "" && c.current != nil {
		id = c.current.sessID
	}
	sess, err := c.app.LoadSession(id)
	if err != nil {
		return fmt.Errorf("no session to analyze: %w", err)
	}
	analyzed, err := c.app.AnalyzeSession(context.Background(), sess)
	if err != nil {
		return err
	}
	c.current = &docSession{sessID: analyzed.ID}
	c.ui.Status("+", "analyzed session %s", analyzed.ID)
	c.printSessionSummary(analyzed)
	return nil
}

func runFindings(c *Console, p *Parsed) error {
	id := ""
	if p.ArgsLen() > 0 {
		id = p.Arg(0)
	} else if c.current != nil {
		id = c.current.sessID
	}
	sess, err := c.app.LoadSession(id)
	if err != nil {
		return fmt.Errorf("no session: %w", err)
	}
	if len(sess.Findings) == 0 {
		c.printf("No findings in session %s (run `analyze` first).\n", sess.ID)
		return nil
	}
	rows := make([][]string, 0, len(sess.SortedFindings()))
	for _, f := range sess.SortedFindings() {
		rows = append(rows, []string{f.RuleID, f.Title, string(f.Severity), string(f.Confidence), f.Target})
	}
	c.ui.Table([]string{"rule", "title", "severity", "confidence", "target"}, rows)
	return nil
}

func runEvidence(c *Console, p *Parsed) error {
	id := ""
	if p.ArgsLen() > 0 {
		id = p.Arg(0)
	} else if c.current != nil {
		id = c.current.sessID
	}
	sess, err := c.app.LoadSession(id)
	if err != nil {
		return fmt.Errorf("no session: %w", err)
	}
	if len(sess.Evidence) == 0 {
		c.printf("No evidence in session %s.\n", sess.ID)
		return nil
	}
	rows := make([][]string, 0, len(sess.Evidence))
	for _, e := range sess.Evidence {
		rows = append(rows, []string{e.ID, string(e.Kind), e.Source, e.Detail})
	}
	c.ui.Table([]string{"id", "kind", "source", "detail"}, rows)
	return nil
}

func runReport(c *Console, p *Parsed) error {
	id := ""
	if c.current != nil {
		id = c.current.sessID
	}
	sess, err := c.app.LoadSession(id)
	if err != nil {
		return fmt.Errorf("no session: %w", err)
	}
	format := "terminal"
	if f := p.Str("format"); f != "" {
		format = f
	}
	if f, err := reporting.ParseFormat(format); err == nil {
		format = string(f)
	}
	content, err := reporting.Render(sess, reporting.Format(format))
	if err != nil {
		return err
	}
	if out := p.Str("out"); out != "" {
		if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(out, []byte(content), 0o644); err != nil {
			return err
		}
		c.ok("report written to %s", out)
		return nil
	}
	c.printf("%s\n", content)
	return nil
}

func runCapabilities(c *Console, _ *Parsed) error {
	list := c.app.Capabilities()
	rows := make([][]string, 0, len(list))
	for _, cap := range list {
		rows = append(rows, []string{cap.ID, cap.Category, cap.Risk, fmt.Sprintf("%v", cap.AuthRequired)})
	}
	c.ui.Table([]string{"id", "category", "risk", "auth"}, rows)
	return nil
}

func runModules(c *Console, _ *Parsed) error {
	c.ui.Section("Assessment modules")
	c.ui.Table([]string{"module", "description"}, [][]string{
		{"discovery", "wireless interface discovery"},
		{"enumeration", "access-point and station enumeration"},
		{"observation", "signal and client observation"},
		{"analysis", "WLAN security rule evaluation"},
		{"validation", "evidence-based confidence escalation"},
		{"findings", "deterministic finding aggregation"},
		{"risk", "transparent risk scoring"},
		{"report", "terminal/json/markdown/html/yaml reports"},
	})
	return nil
}

func runOptions(c *Console, _ *Parsed) error {
	c.ui.KV("interface", orNone(c.iface))
	c.ui.KV("simulation", boolWord(c.sim))
	c.ui.KV("authorized", boolWord(c.authorized))
	backend := c.app.Backend.Name()
	if c.sim {
		backend = "simulation"
	}
	c.ui.KV("backend", backend)
	c.ui.KV("current session", orNone(currentID(c.current)))
	return nil
}

func runTarget(c *Console, p *Parsed) error {
	switch p.Arg(0) {
	case "show", "":
		return runStatus(c, p)
	case "list":
		rows := make([][]string, 0)
		for _, t := range c.app.Targets.List() {
			rows = append(rows, []string{t.ID, string(t.Type), t.Value, fmt.Sprintf("%v", t.Authorized())})
		}
		if len(rows) == 0 {
			c.printf("No saved targets.\n")
			return nil
		}
		c.ui.Table([]string{"id", "type", "value", "authorized"}, rows)
		return nil
	default:
		return fmt.Errorf("unknown target subcommand %q (show, list)", p.Arg(0))
	}
}

func runSession(c *Console, p *Parsed) error {
	if p.ArgsLen() == 1 {
		sess, err := c.app.LoadSession(p.Arg(0))
		if err != nil {
			return err
		}
		c.ui.KV("session", sess.ID)
		c.ui.KV("target", sess.Target)
		c.ui.KV("interface", orNone(sess.Interface))
		c.ui.KV("findings", fmt.Sprintf("%d", len(sess.Findings)))
		c.ui.KV("risk", fmt.Sprintf("%d/100 (%s)", sess.RiskScore, sess.RiskLevel))
		return nil
	}
	ids, err := c.app.Store.List()
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		c.printf("No sessions yet. Run `scan` or `run` first.\n")
		return nil
	}
	rows := make([][]string, 0, len(ids))
	for _, id := range ids {
		sess, _ := c.app.LoadSession(id)
		if sess == nil {
			rows = append(rows, []string{id, "-", "-", "-"})
			continue
		}
		rows = append(rows, []string{id, sess.Target, fmt.Sprintf("%d", len(sess.Findings)),
			fmt.Sprintf("%d (%s)", sess.RiskScore, sess.RiskLevel)})
	}
	c.ui.Table([]string{"session", "target", "findings", "risk"}, rows)
	return nil
}

func runEvents(c *Console, p *Parsed) error {
	id := ""
	if p.ArgsLen() > 0 {
		id = p.Arg(0)
	} else if c.current != nil {
		id = c.current.sessID
	}
	sess, err := c.app.LoadSession(id)
	if err != nil {
		return fmt.Errorf("no session: %w", err)
	}
	rows := make([][]string, 0, len(sess.Stages))
	for _, s := range sess.Stages {
		rows = append(rows, []string{s, "completed"})
	}
	c.ui.Table([]string{"stage", "status"}, rows)
	return nil
}

func runHistory(c *Console, _ *Parsed) error {
	for i, line := range c.hist.Lines() {
		c.printf("%4d  %s\n", i+1, line)
	}
	return nil
}

func runClear(c *Console, _ *Parsed) error {
	if c.out == os.Stdout {
		_, _ = fmt.Fprint(c.out, "\x1b[H\x1b[2J")
	}
	return nil
}

func runBanner(c *Console, _ *Parsed) error {
	c.ui.Banner("Wireless Security Assessment Framework")
	return nil
}

func runCompletion(c *Console, _ *Parsed) error {
	c.printf("Shell completion scripts are generated with the one-shot command:\n")
	c.printf("  mansa completion bash|zsh|fish|powershell\n")
	return nil
}

func runUpdates(c *Console, _ *Parsed) error {
	c.ui.Status("*", "checking for updates...")
	cfg := selfupdate.Config{
		Owner:          "QYVORA",
		Repo:           "qyvora-mansa",
		ToolName:       "mansa",
		CurrentVersion: func() string { return version.Version },
	}
	result := selfupdate.Run(c.OpContext(), cfg, c.out)
	c.printf("  status: %s (current %s)\n", result.Status, result.Current)
	if result.Latest != "" {
		c.printf("  latest: %s\n", result.Latest)
	}
	if result.Error != "" && result.Status != "current" {
		return fmt.Errorf("update check failed: %s", result.Error)
	}
	return nil
}

// ---- helpers ----------------------------------------------------------

func (c *Console) renderAPs(sess *models.Session, p *Parsed) {
	aps := pipeline.FilterBySSID(sess.AccessPoints, p.Str("ssid"))
	aps = pipeline.FilterByBSSID(aps, p.Str("bssid"))
	aps = pipeline.FilterByBand(aps, p.Str("band"))
	c.ui.Section(fmt.Sprintf("Access points (%d/%d)", len(aps), len(sess.AccessPoints)))
	if len(aps) == 0 {
		c.printf("  (none)\n")
		return
	}
	rows := make([][]string, 0, len(aps))
	for _, ap := range aps {
		sec := ap.Security.Auth
		if sec == "" {
			sec = "open"
		}
		rows = append(rows, []string{ap.BSSID, ap.SSID, fmt.Sprintf("%d", ap.Channel), ap.Band,
			fmt.Sprintf("%d", ap.Signal), sec, ap.Vendor})
	}
	c.ui.Table([]string{"bssid", "ssid", "ch", "band", "signal", "security", "vendor"}, rows)
}

func (c *Console) printSessionSummary(sess *models.Session) {
	c.ui.Section("Assessment summary")
	c.ui.KV("session", sess.ID)
	c.ui.KV("target", sess.Target)
	c.ui.KV("interface", orNone(sess.Interface))
	c.ui.KV("access points", fmt.Sprintf("%d", len(sess.AccessPoints)))
	c.ui.KV("stations", fmt.Sprintf("%d", len(sess.Stations)))
	c.ui.KV("findings", fmt.Sprintf("%d", len(sess.Findings)))
	c.ui.KV("risk", fmt.Sprintf("%d/100 (%s)", sess.RiskScore, sess.RiskLevel))
	if len(sess.Errors) > 0 {
		for _, e := range sess.Errors {
			c.ui.Status("x", "%s", e)
		}
	}
}

func summaryOf(sess *models.Session) string {
	return fmt.Sprintf("%d APs, %d findings, risk %d/100 (%s)",
		len(sess.AccessPoints), len(sess.Findings), sess.RiskScore, sess.RiskLevel)
}

func currentID(d *docSession) string {
	if d == nil {
		return ""
	}
	return d.sessID
}

func simSuffix(sim bool) string {
	if sim {
		return " (simulation)"
	}
	return ""
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func boolWord(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
