// Package rules defines the deterministic analysis rule model for Mansa.
// Each Rule is a pure function that inspects the session and produces
// zero or more findings.
package rules

import (
	"sort"

	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// Rule is one deterministic security rule.
type Rule struct {
	ID          string
	Name        string
	Category    string
	Description string
	Severity    models.Severity
	Confidence  models.Confidence
	Detect      func(ctx *Context) []models.Finding
	Remediation string
	References  []string
}

// Context is the read-only input provided to each rule's Detect function.
type Context struct {
	Session      *models.Session
	APs          []models.AccessPoint
	Stations     []models.Station
	Observations []models.WirelessObservation
	Traffic      []models.TrafficObservation
}

// NewContext creates a Context from a session.
func NewContext(sess *models.Session) *Context {
	return &Context{
		Session:      sess,
		APs:          sess.AccessPoints,
		Stations:     sess.Stations,
		Observations: sess.Observations,
		Traffic:      sess.Traffic,
	}
}

// Engine runs rules against a context.
type Engine struct {
	rules []*Rule
}

// NewEngine creates an empty rule engine.
func NewEngine() *Engine { return &Engine{} }

// Add registers a rule.
func (e *Engine) Add(r *Rule) { e.rules = append(e.rules, r) }

// AddMany registers multiple rules.
func (e *Engine) AddMany(rs []*Rule) { e.rules = append(e.rules, rs...) }

// Rules returns the registered rules (copy).
func (e *Engine) Rules() []*Rule {
	out := make([]*Rule, len(e.rules))
	copy(out, e.rules)
	return out
}

// Eval runs all rules and returns sorted, deduplicated findings.
func (e *Engine) Eval(ctx *Context, sessionID string) []models.Finding {
	var all []models.Finding
	for _, r := range e.rules {
		findings := r.Detect(ctx)
		for i := range findings {
			findings[i].RuleID = r.ID
			findings[i].Recommendation = r.Remediation
			findings[i].References = r.References
			if sessionID != "" {
				findings[i].Target = sessionID
			}
		}
		all = append(all, findings...)
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Severity.Weight() != all[j].Severity.Weight() {
			return all[i].Severity.Weight() > all[j].Severity.Weight()
		}
		if all[i].RuleID != all[j].RuleID {
			return all[i].RuleID < all[j].RuleID
		}
		return all[i].Title < all[j].Title
	})
	return all
}
