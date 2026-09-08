// Package pipeline implements the Mansa assessment stage runner.
// Stages: discover → enumerate → observe → analyze → validate → findings → risk → report.
package pipeline

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/QYVORA/qyvora-mansa/internal/events"
	"github.com/QYVORA/qyvora-mansa/internal/rules"
	"github.com/QYVORA/qyvora-mansa/internal/rules/builtin"
	"github.com/QYVORA/qyvora-mansa/internal/transport"
	"github.com/QYVORA/qyvora-mansa/internal/wireless"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

const (
	StageDiscover  = "discover"
	StageEnumerate = "enumerate"
	StageObserve   = "observe"
	StageAnalyze   = "analyze"
	StageValidate  = "validate"
	StageFindings  = "findings"
	StageRisk      = "risk"
	StageReport    = "report"
)

// StageOrder is the canonical stage sequence.
var StageOrder = []string{
	StageDiscover, StageEnumerate, StageObserve, StageAnalyze,
	StageValidate, StageFindings, StageRisk, StageReport,
}

// Env is the shared environment for all stages.
type Env struct {
	Backend  transport.Backend
	Session  *models.Session
	Events   *events.Stream
	Offline  bool
	ReportFn func(ctx context.Context, sess *models.Session) error // called at report stage
}

// Runner executes pipeline stages sequentially.
type Runner struct{}

// Run runs all stages.
func (r *Runner) Run(ctx context.Context, env *Env) error {
	return r.RunUntil(ctx, env, "")
}

// RunUntil runs stages until stopAfter (inclusive). Empty = run all.
func (r *Runner) RunUntil(ctx context.Context, env *Env, stopAfter string) error {
	names := StageOrder
	if stopAfter != "" {
		valid := false
		for _, s := range StageOrder {
			if s == stopAfter {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("unknown pipeline stage %q", stopAfter)
		}
		for i, s := range StageOrder {
			if s == stopAfter {
				names = StageOrder[:i+1]
				break
			}
		}
	}
	return r.runAll(ctx, env, names)
}

// RunStages runs only the named stages in order, without re-running earlier
// stages. It is used for re-analyzing an existing session on disk, where
// discovery and enumeration data must not be re-collected.
func (r *Runner) RunStages(ctx context.Context, env *Env, stages []string) error {
	return r.runAll(ctx, env, stages)
}

func (r *Runner) runAll(ctx context.Context, env *Env, names []string) error {
	if env.Events != nil {
		env.Events.Info(events.ScanStarted, map[string]any{
			"target":  env.Session.Target,
			"offline": env.Offline,
		})
	}
	var fatal error
	for _, name := range names {
		valid := false
		for _, s := range StageOrder {
			if s == name {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("unknown pipeline stage %q", name)
		}
		if ctx.Err() != nil {
			fatal = ctx.Err()
			break
		}
		env.Session.Stages = append(env.Session.Stages, name)
		if env.Events != nil {
			env.Events.Info(events.StageStarted, map[string]any{"stage": name})
		}
		err := runStage(name, ctx, env)
		data := map[string]any{"stage": name}
		if err != nil {
			data["error"] = err.Error()
			env.Session.Errors = append(env.Session.Errors, name+": "+err.Error())
			if env.Events != nil {
				env.Events.Fail(events.StageCompleted, data)
			}
			fatal = err
			break
		}
		if env.Events != nil {
			env.Events.Info(events.StageCompleted, data)
		}
	}
	env.Session.Finish()
	if env.Events != nil {
		env.Events.Info(events.ScanCompleted, map[string]any{
			"target":        env.Session.Target,
			"stages":        len(env.Session.Stages),
			"access_points": len(env.Session.AccessPoints),
			"findings":      len(env.Session.Findings),
			"risk_level":    env.Session.RiskLevel,
		})
	}
	return fatal
}

func runStage(name string, ctx context.Context, env *Env) error {
	switch name {
	case StageDiscover:
		return stageDiscover(ctx, env)
	case StageEnumerate:
		return stageEnumerate(ctx, env)
	case StageObserve:
		return stageObserve(ctx, env)
	case StageAnalyze:
		return stageAnalyze(ctx, env)
	case StageValidate:
		return stageValidate(ctx, env)
	case StageFindings:
		return stageFindings(ctx, env)
	case StageRisk:
		return stageRisk(ctx, env)
	case StageReport:
		return stageReport(ctx, env)
	default:
		return fmt.Errorf("unknown stage %q", name)
	}
}

func stageDiscover(_ context.Context, env *Env) error {
	ifaces, err := env.Backend.DiscoverInterfaces()
	if err != nil {
		return err
	}
	env.Session.Interfaces = ifaces
	if env.Session.Interface == "" && len(ifaces) > 0 {
		env.Session.Interface = ifaces[0].Name
	}
	if env.Events != nil {
		for _, iface := range ifaces {
			env.Events.Info(events.InterfaceDiscovered, map[string]any{
				"name": iface.Name, "state": iface.State,
			})
		}
	}
	return nil
}

func stageEnumerate(ctx context.Context, env *Env) error {
	aps, stations, err := env.Backend.Scan(ctx, env.Session.Interface, 30)
	if err != nil {
		return err
	}
	for i := range aps {
		wireless.NormalizeAP(&aps[i])
	}
	env.Session.AccessPoints = aps
	env.Session.Stations = stations
	if env.Events != nil {
		for _, ap := range aps {
			env.Events.Info(events.AccessPointDiscovered, map[string]any{
				"bssid": ap.BSSID, "ssid": ap.SSID,
				"channel": ap.Channel, "band": ap.Band,
				"security": ap.Security.Auth,
			})
		}
		for _, st := range stations {
			env.Events.Info(events.ClientDiscovered, map[string]any{
				"mac": st.MAC, "ap": st.APBSSID,
			})
		}
	}
	return nil
}

func stageObserve(_ context.Context, env *Env) error {
	now := models.NewID("obs")
	for _, ap := range env.Session.AccessPoints {
		o := models.WirelessObservation{
			ID:         now,
			Key:        "ap.signal",
			Value:      fmt.Sprintf("%d", ap.Signal),
			Target:     ap.BSSID,
			Source:     "pipeline",
			Confidence: models.ConfObserved,
		}
		env.Session.AddObservation(o)
		if env.Events != nil {
			env.Events.Info(events.ObservationCollected, map[string]any{
				"target": ap.BSSID, "key": "ap.signal",
			})
		}
	}
	return nil
}

func stageAnalyze(_ context.Context, env *Env) error {
	ctx := rules.NewContext(env.Session)
	engine := rules.NewEngine()
	engine.AddMany(builtin.All())
	findings := engine.Eval(ctx, env.Session.ID)
	for _, f := range findings {
		env.Session.AddFinding(f)
		if env.Events != nil {
			env.Events.Info(events.FindingDiscovered, map[string]any{
				"rule_id": f.RuleID, "title": f.Title,
				"severity": string(f.Severity), "target": f.Target,
			})
		}
	}
	return nil
}

func stageValidate(_ context.Context, env *Env) error {
	for i, f := range env.Session.Findings {
		if len(f.Evidence) > 0 {
			env.Session.Findings[i].Confidence = models.ConfObserved
		}
	}
	unverified := 0
	for _, f := range env.Session.Findings {
		if len(f.Evidence) == 0 {
			unverified++
		}
	}
	if env.Session.Attributes == nil {
		env.Session.Attributes = map[string]string{}
	}
	env.Session.Attributes["findings.unverified"] = fmt.Sprintf("%d", unverified)
	if env.Events != nil {
		env.Events.Info(events.AnalysisCompleted, map[string]any{
			"total":      len(env.Session.Findings),
			"unverified": unverified,
		})
	}
	return nil
}

func stageFindings(_ context.Context, env *Env) error {
	findings := env.Session.SortedFindings()
	env.Session.Findings = findings
	return nil
}

func stageRisk(_ context.Context, env *Env) error {
	sess := env.Session
	if len(sess.Findings) == 0 {
		sess.RiskScore = 0
		sess.RiskLevel = "none"
		return nil
	}
	total := 0
	for _, f := range sess.Findings {
		total += models.ScoreFor(f)
	}
	avg := total / len(sess.Findings)
	sess.RiskScore = avg
	sess.RiskLevel = string(models.LevelFromScore(avg))
	if env.Events != nil {
		env.Events.Info(events.RiskCalculated, map[string]any{
			"score": avg, "level": sess.RiskLevel,
		})
	}
	return nil
}

func stageReport(ctx context.Context, env *Env) error {
	if env.ReportFn != nil {
		return env.ReportFn(ctx, env.Session)
	}
	return nil
}

// FilterBySSID filters access points to those matching ssid.
func FilterBySSID(aps []models.AccessPoint, ssid string) []models.AccessPoint {
	ssid = strings.ToLower(strings.TrimSpace(ssid))
	if ssid == "" {
		return aps
	}
	var out []models.AccessPoint
	for _, ap := range aps {
		if strings.ToLower(ap.SSID) == ssid {
			out = append(out, ap)
		}
	}
	return out
}

// FilterByBSSID filters access points to those matching bssid.
func FilterByBSSID(aps []models.AccessPoint, bssid string) []models.AccessPoint {
	bssid = strings.ToUpper(strings.TrimSpace(bssid))
	if bssid == "" {
		return aps
	}
	var out []models.AccessPoint
	for _, ap := range aps {
		if strings.ToUpper(ap.BSSID) == bssid {
			out = append(out, ap)
		}
	}
	return out
}

// FilterByBand filters access points to those matching band.
func FilterByBand(aps []models.AccessPoint, band string) []models.AccessPoint {
	band = strings.TrimSpace(band)
	if band == "" {
		return aps
	}
	var out []models.AccessPoint
	for _, ap := range aps {
		if strings.EqualFold(ap.Band, band) {
			out = append(out, ap)
		}
	}
	return out
}

// ChannelSummary returns sorted channel summary strings.
func ChannelSummary(aps []models.AccessPoint) []string {
	counts := make(map[int]int)
	for _, ap := range aps {
		counts[ap.Channel]++
	}
	type chCount struct{ ch, count int }
	items := make([]chCount, 0, len(counts))
	for ch, count := range counts {
		items = append(items, chCount{ch, count})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ch < items[j].ch })
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, fmt.Sprintf("Ch %d: %d APs", item.ch, item.count))
	}
	return out
}
