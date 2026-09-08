// Package capabilities provides the machine-readable capability registry
// for Mansa. This is the contract a future QYVORA AI orchestrator can
// consume.
package capabilities

import (
	"sort"
)

// ContractVersion is the capability schema version.
const ContractVersion = "1.0"

// Tool describes one atomic Mansa capability.
type Tool struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Framework    string   `json:"framework"`
	Category     string   `json:"category"`
	Output       []string `json:"output,omitempty"`
	Risk         string   `json:"risk"`
	AuthRequired bool     `json:"authorization_required"`
	Confirm      bool     `json:"confirmation_required"`
	Reversible   bool     `json:"reversible"`
	ChangesState bool     `json:"changes_state"`
	Targets      []string `json:"target_types,omitempty"`
	Duration     string   `json:"duration,omitempty"`
	Schema       Schema   `json:"schema"`
}

// Param describes one input parameter.
type Param struct {
	Name        string `json:"name"`
	Type        string `json:"type,omitempty"`
	Required    bool   `json:"required,omitempty"`
	Description string `json:"description,omitempty"`
}

// OutputField describes one output field.
type OutputField struct {
	Name        string `json:"name"`
	Type        string `json:"type,omitempty"`
	Description string `json:"description,omitempty"`
}

// Schema is the input/output schema for a tool.
type Schema struct {
	Input  []Param       `json:"input"`
	Output []OutputField `json:"output"`
}

// Registry returns all Mansa capabilities as a Tool list.
func Registry() []Tool {
	tools := []Tool{
		{
			ID:          "mansa.discover",
			Name:        "Discover Interfaces",
			Description: "Discover wireless interfaces and their capabilities",
			Framework:   "mansa", Category: "discovery",
			Output: []string{"wireless_interfaces", "supported_bands", "supported_channels"},
			Risk:   "low", AuthRequired: false, Reversible: true,
			Targets: []string{"interface"},
			Schema: Schema{
				Input:  []Param{{Name: "interface", Type: "string", Required: false, Description: "specific interface to inspect"}},
				Output: []OutputField{{Name: "interfaces", Type: "[]WirelessInterface", Description: "discovered interfaces"}},
			},
		},
		{
			ID:          "mansa.scan",
			Name:        "Wireless Scan",
			Description: "Scan for wireless networks and access points",
			Framework:   "mansa", Category: "enumeration",
			Output: []string{"access_points", "stations", "observations"},
			Risk:   "medium", AuthRequired: true, Reversible: true,
			Targets: []string{"interface", "ssid", "bssid"},
			Schema: Schema{
				Input:  []Param{{Name: "interface", Type: "string", Required: true}, {Name: "timeout", Type: "duration", Required: false}},
				Output: []OutputField{{Name: "access_points", Type: "[]AccessPoint", Description: "discovered access points"}},
			},
		},
		{
			ID:          "mansa.enumerate",
			Name:        "Access Point Enumeration",
			Description: "Enumerate detailed information about discovered access points",
			Framework:   "mansa", Category: "enumeration",
			Output: []string{"access_points", "channels", "vendors"},
			Risk:   "low", AuthRequired: true, Reversible: true,
			Targets: []string{"interface"},
			Schema: Schema{
				Input:  []Param{{Name: "interface", Type: "string", Required: true}, {Name: "ssid", Type: "string"}, {Name: "bssid", Type: "string"}, {Name: "band", Type: "string"}},
				Output: []OutputField{{Name: "access_points", Type: "[]AccessPoint", Description: "detailed AP inventory"}},
			},
		},
		{
			ID:          "mansa.observe",
			Name:        "Observe Wireless Clients",
			Description: "Observe wireless stations and client behavior",
			Framework:   "mansa", Category: "observation",
			Output: []string{"stations", "observations"},
			Risk:   "low", AuthRequired: true, Reversible: true,
			Targets: []string{"interface"},
			Schema: Schema{
				Input:  []Param{{Name: "interface", Type: "string", Required: true}},
				Output: []OutputField{{Name: "stations", Type: "[]Station", Description: "wireless clients"}},
			},
		},
		{
			ID:          "mansa.analyze",
			Name:        "Security Analysis",
			Description: "Analyze wireless security configuration and generate findings",
			Framework:   "mansa", Category: "analysis",
			Output: []string{"findings", "evidence"},
			Risk:   "low", AuthRequired: false, Reversible: true,
			Targets: []string{"session"},
			Schema: Schema{
				Input:  []Param{{Name: "session", Type: "string", Required: true, Description: "session ID"}},
				Output: []OutputField{{Name: "findings", Type: "[]Finding", Description: "security findings"}},
			},
		},
		{
			ID:          "mansa.findings",
			Name:        "View Findings",
			Description: "Display security findings from the current or latest session",
			Framework:   "mansa", Category: "reporting",
			Output: []string{"findings"},
			Risk:   "low", AuthRequired: false, Reversible: true,
			Targets: []string{"session"},
			Schema: Schema{
				Input:  []Param{{Name: "session", Type: "string"}},
				Output: []OutputField{{Name: "findings", Type: "[]Finding"}},
			},
		},
		{
			ID:          "mansa.evidence",
			Name:        "View Evidence",
			Description: "Display collected evidence supporting findings",
			Framework:   "mansa", Category: "reporting",
			Output: []string{"evidence"},
			Risk:   "low", AuthRequired: false, Reversible: true,
			Targets: []string{"session"},
			Schema: Schema{
				Input:  []Param{{Name: "session", Type: "string"}},
				Output: []OutputField{{Name: "evidence", Type: "[]Evidence"}},
			},
		},
		{
			ID:          "mansa.report",
			Name:        "Generate Report",
			Description: "Generate a formatted security assessment report",
			Framework:   "mansa", Category: "reporting",
			Output: []string{"report"},
			Risk:   "low", AuthRequired: false, Reversible: true,
			Targets: []string{"session"},
			Schema: Schema{
				Input:  []Param{{Name: "session", Type: "string"}, {Name: "format", Type: "string"}},
				Output: []OutputField{{Name: "report", Type: "string", Description: "formatted report"}},
			},
		},
		{
			ID:          "mansa.assess",
			Name:        "Full Assessment Pipeline",
			Description: "Run the complete wireless security assessment pipeline",
			Framework:   "mansa", Category: "assessment",
			Output: []string{"findings", "evidence", "report", "risk"},
			Risk:   "medium", AuthRequired: true, Reversible: true,
			Targets: []string{"interface", "simulation"},
			Schema: Schema{
				Input:  []Param{{Name: "interface", Type: "string"}, {Name: "sim", Type: "bool"}},
				Output: []OutputField{{Name: "session", Type: "Session", Description: "completed session"}},
			},
		},
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].ID < tools[j].ID })
	return tools
}
