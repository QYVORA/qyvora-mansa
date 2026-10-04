// Package capabilities provides the machine-readable capability registry
// for Mansa. This is the contract a future QYVORA AI orchestrator can
// consume.
package capabilities

import (
	"fmt"
	"sort"

	"github.com/QYVORA/qyvora-mansa/internal/active"
	"github.com/QYVORA/qyvora-mansa/internal/exploitation"
	"github.com/QYVORA/qyvora-mansa/internal/operation"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// ContractVersion is the capability schema version.
const ContractVersion = "1.0"

// Tool describes one atomic Mansa capability.
type Tool struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	Description         string   `json:"description"`
	Framework           string   `json:"framework"`
	Category            string   `json:"category"`
	Output              []string `json:"output,omitempty"`
	Risk                string   `json:"risk"`
	AuthRequired        bool     `json:"authorization_required"`
	SimulationSupported bool     `json:"simulation_supported,omitempty"`
	Confirm             bool     `json:"confirmation_required"`
	Reversible          bool     `json:"reversible"`
	ChangesState        bool     `json:"changes_state"`
	Targets             []string `json:"target_types,omitempty"`
	Duration            string   `json:"duration,omitempty"`
	// HardwareCapability names the runtime capability whose observed state
	// answers "can this host do this?", which is a different question from
	// whether the binary implements it. Empty means the tool needs no radio:
	// it reads a file, a session, or a report, so hardware state is not
	// applicable rather than unknown.
	HardwareCapability string `json:"hardware_capability,omitempty"`
	Schema             Schema `json:"schema"`
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
			HardwareCapability: models.HardwareWiFiInterfaceDiscovery,
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
			HardwareCapability: models.HardwareWiFiAPEnumeration,
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
			HardwareCapability: models.HardwareWiFiAPEnumeration,
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
			HardwareCapability: models.HardwareWiFiClientObservation,
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
			ID:          "mansa.capture.analyze",
			Name:        "Offline PCAP Analysis",
			Description: "Analyze access points and observed clients from a PCAP or PCAPNG capture and save an evidence-backed session",
			Framework:   "mansa", Category: "offline-analysis",
			Output: []string{"access_points", "stations", "wireless_authentication", "eapol_messages", "four_way_message_sets_observed", "pmkid_observations", "wep_capture_conditions", "findings", "evidence", "session"},
			Risk:   "low", AuthRequired: false, Reversible: true,
			Targets: []string{"capture"},
			Schema: Schema{
				Input:  []Param{{Name: "pcap_file", Type: "path", Required: true, Description: "PCAP/PCAPNG file with raw 802.11 or radiotap link type"}},
				Output: []OutputField{{Name: "session", Type: "Session", Description: "saved offline capture analysis session"}, {Name: "four_way_message_sets_observed", Type: "uint64", Description: "M1/M2 and M3/M4 observed with matching replay counters; not MIC or credential verification"}, {Name: "wep_capture_conditions", Type: "WEPObservation", Description: "bounded legacy-IV reuse indicators when a captured AP advertises WEP; not key recovery evidence"}},
			},
		},
		{
			ID:          "mansa.capture.live",
			Name:        "Passive Live Capture",
			Description: "Passively capture raw 802.11 frames from an existing monitor interface to a new PCAP file",
			Framework:   "mansa", Category: "capture",
			Output: []string{"pcap_file", "capture_statistics", "session", "evidence", "findings"},
			Risk:   "medium", AuthRequired: true, Confirm: true, Reversible: true, SimulationSupported: true,
			Targets: []string{"interface"}, Duration: "maximum 1h",
			Schema: Schema{
				Input:  []Param{{Name: "interface", Type: "string", Required: false, Description: "required for live capture; defaults to sim0 in simulation"}, {Name: "monitor-interface", Type: "string", Required: false, Description: "create and remove a temporary monitor interface from interface"}, {Name: "out", Type: "path", Required: false, Description: "new file path; defaults to capture.pcap"}, {Name: "duration", Type: "duration", Required: false, Description: "defaults to 1m; maximum 1h"}, {Name: "channel", Type: "int", Required: false, Description: "fixed radio-reported channel; restores the prior channel after capture"}, {Name: "hop", Type: "[]int", Required: false, Description: "radio-reported channel numbers to cycle through"}, {Name: "dwell", Type: "duration", Required: false, Description: "per-channel dwell duration while hopping"}, {Name: "prefilter", Type: "string", Required: false, Description: "kernel prefilter mode: assessment, management, beacon, or all"}, {Name: "prefilter-address", Type: "string", Required: false, Description: "restrict the kernel prefilter to frames involving this MAC address"}, {Name: "sim", Type: "bool", Required: false}},
				Output: []OutputField{{Name: "packets", Type: "uint64"}, {Name: "bytes", Type: "uint64"}, {Name: "link_type", Type: "uint32"}},
			},
			HardwareCapability: models.HardwareWiFiRawCapture,
		},
		{
			ID: "mansa.bluetooth.advertisement.parse", Name: "Parse BLE Advertisement",
			Description: "Parse a captured BLE advertising payload into normalized names, service UUIDs, TX power, and manufacturer data",
			Framework:   "mansa", Category: "offline-analysis", Output: []string{"advertisement"},
			Risk: "low", AuthRequired: false, Reversible: true, SimulationSupported: true, Targets: []string{"capture"},
			Schema: Schema{
				Input:  []Param{{Name: "payload_hex", Type: "hex", Required: false}, {Name: "sim", Type: "bool", Required: false}},
				Output: []OutputField{{Name: "advertisement", Type: "BLEAdvertisement"}},
			},
		},
		{
			ID: "mansa.bluetooth.gatt.analyze", Name: "Analyze GATT Metadata",
			Description: "Review saved GATT metadata for writable characteristics without reported encryption, authentication, or authorization requirements",
			Framework:   "mansa", Category: "offline-analysis", Output: []string{"findings"},
			Risk: "low", AuthRequired: false, Reversible: true, SimulationSupported: true, Targets: []string{"capture"},
			Schema: Schema{
				Input:  []Param{{Name: "database_json", Type: "path", Required: false}, {Name: "sim", Type: "bool", Required: false}},
				Output: []OutputField{{Name: "findings", Type: "[]Finding"}},
			},
		},
		{
			ID: "mansa.bluetooth.adapters", Name: "Discover Bluetooth Adapters",
			Description: "List Linux HCI adapter metadata from sysfs without powering on, scanning, or connecting",
			Framework:   "mansa", Category: "discovery", Output: []string{"bluetooth_adapters"},
			Risk: "low", AuthRequired: false, Reversible: true, Targets: []string{"bluetooth-adapter"},
			Schema:             Schema{Input: []Param{}, Output: []OutputField{{Name: "adapters", Type: "[]BluetoothAdapter"}}},
			HardwareCapability: models.HardwareBluetoothAdapterDiscovery,
		},
		{
			ID: "mansa.bluetooth.hci.parse", Name: "Parse HCI Advertising Reports",
			Description: "Decode captured legacy and extended HCI LE Advertising Report events into normalized BLE device observations",
			Framework:   "mansa", Category: "offline-analysis", Output: []string{"bluetooth_devices"},
			Risk: "low", AuthRequired: false, Reversible: true, SimulationSupported: true, Targets: []string{"capture"},
			Schema: Schema{Input: []Param{{Name: "hci_packet_hex", Type: "hex", Required: false}, {Name: "sim", Type: "bool", Required: false}}, Output: []OutputField{{Name: "observations", Type: "[]BluetoothDeviceObservation"}}},
		},
		{
			ID: "mansa.bluetooth.scan", Name: "Passive BLE Discovery",
			Description: "Passively scan LE advertisements from an already powered HCI adapter; does not connect to devices or power the adapter",
			Framework:   "mansa", Category: "discovery", Output: []string{"bluetooth_devices", "session", "evidence"},
			Risk: "medium", AuthRequired: true, Confirm: true, Reversible: true, SimulationSupported: true,
			Targets: []string{"bluetooth-adapter"}, Duration: "maximum 10m",
			Schema:             Schema{Input: []Param{{Name: "adapter", Type: "string", Required: true}, {Name: "duration", Type: "duration", Required: false}, {Name: "sim", Type: "bool", Required: false}}, Output: []OutputField{{Name: "devices", Type: "[]BluetoothDeviceObservation"}, {Name: "session", Type: "Session"}}},
			HardwareCapability: models.HardwareBLEDiscovery,
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
			ID: "mansa.bluetooth.gatt.enumerate", Name: "Enumerate Live GATT Services",
			Description: "Enumerate a peer's live GATT services, characteristics, and descriptors over ATT without writing to or pairing with the peer",
			Framework:   "mansa", Category: "discovery", Output: []string{"gatt_database"},
			Risk: "low", AuthRequired: true, Reversible: true, Targets: []string{"bluetooth-adapter"},
			HardwareCapability: models.HardwareBLEGATT,
			Schema: Schema{
				Input:  []Param{{Name: "adapter", Type: "string", Required: false}, {Name: "address", Type: "string", Required: true, Description: "peer address to enumerate"}},
				Output: []OutputField{{Name: "services", Type: "[]GATTService", Description: "services, characteristics, and descriptors the peer exposes"}},
			},
		},
		{
			ID: "mansa.credentials.verify", Name: "Verify Candidate Passphrases",
			Description: "Recompute the message integrity code of a captured four-way handshake against candidate passphrases and report which candidate, if any, the peer accepted",
			Framework:   "mansa", Category: "analysis", Output: []string{"credentials", "findings"},
			Risk: "medium", AuthRequired: false, Reversible: true, Targets: []string{"capture"},
			Schema: Schema{
				Input: []Param{
					{Name: "handshake", Type: "path", Required: true, Description: "captured handshake material"},
					{Name: "wordlist", Type: "path", Required: false, Description: "candidate passphrase list"},
				},
				Output: []OutputField{{Name: "result", Type: "CredentialResult", Description: "which candidate matched, or that none did"}},
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
			HardwareCapability: models.HardwareWiFiInterfaceDiscovery,
		},
	}
	tools = append(tools, operationTools()...)
	sort.Slice(tools, func(i, j int) bool { return tools[i].ID < tools[j].ID })
	return tools
}

// operationRegistry is the single module registry. Every surface — the CLI, the
// operation executor, and this capability contract — reads it, so a module cannot
// exist in one place and be missing from another.
func operationRegistry() *operation.Registry {
	registry := operation.NewRegistry()
	for _, module := range active.BluetoothModules() {
		registry.MustRegister(module)
	}
	for _, module := range active.WiFiModules() {
		registry.MustRegister(module)
	}
	exploitation.NewRegistry(registry).MustRegister(exploitation.Builtins()...)
	return registry
}

// operationCommand is the CLI verb a class runs under.
func operationCommand(class models.OperationClass) string {
	switch class {
	case models.ClassValidation:
		return "validate"
	case models.ClassActiveTest:
		return "test"
	case models.ClassExploitation:
		return "exploit"
	case models.ClassPassive:
		return "observe"
	default:
		return string(class)
	}
}

// operationTools derives the capability contract from the module registry rather
// than restating it, so the published contract cannot claim a capability the
// binary does not provide or omit one it does.
func operationTools() []Tool {
	metas := operationRegistry().List()
	tools := make([]Tool, 0, len(metas))
	for _, meta := range metas {
		inputs := make([]Param, 0, len(meta.Parameters)+5)
		inputs = append(inputs,
			Param{Name: "target", Type: "string", Required: true, Description: "authorized target: a stored target id, a literal address or name, or 'auto' to use the interface"},
			Param{Name: "interface", Type: "string", Description: "wireless interface the operation uses"},
			Param{Name: "session", Type: "string", Description: "session supplying collected observations, or 'latest'"},
			Param{Name: "database", Type: "path", Description: "saved GATT attribute table JSON"},
			Param{Name: "operator", Type: "string", Description: "identity recorded as responsible for the run"},
			Param{Name: "sim", Type: "bool", Description: "run the simulation path; no over-air action is taken"},
			Param{Name: "dry_run", Type: "bool", Description: "print the plan without transmitting or collecting"},
		)
		for _, parameter := range meta.Parameters {
			inputs = append(inputs, Param{
				Name: parameter.Name, Type: parameter.Kind, Required: parameter.Required,
				Description: parameter.Description,
			})
		}
		targets := make([]string, 0, len(meta.TargetTypes))
		for _, targetType := range meta.TargetTypes {
			targets = append(targets, string(targetType))
		}
		description := meta.Description
		if meta.VulnerabilityClass != "" {
			description = fmt.Sprintf("%s Vulnerability class: %s. Affected component: %s.",
				description, meta.VulnerabilityClass, meta.Component)
		}
		if len(meta.Prerequisites) > 0 {
			description = fmt.Sprintf("%s Prerequisites: %s.", description, joinPhrases(meta.Prerequisites))
		}
		if len(meta.Limitations) > 0 {
			description = fmt.Sprintf("%s Stated limitations: %s.", description, joinPhrases(meta.Limitations))
		}
		if meta.Cleanup != "" {
			description = fmt.Sprintf("%s Cleanup: %s.", description, meta.Cleanup)
		}
		duration := ""
		if meta.MaxDuration > 0 {
			duration = "maximum " + meta.MaxDuration.String()
		}
		tools = append(tools, Tool{
			ID:          "mansa." + operationCommand(meta.Class) + "." + meta.ID,
			Name:        meta.Title,
			Description: description,
			Framework:   "mansa",
			Category:    string(meta.Class),
			Output:      []string{"operation_record", "findings", "evidence"},
			Risk:        meta.Risk,
			// Every non-simulated run passes the authorization gate, so the
			// contract reports it for all classes rather than implying that
			// validation is exempt.
			AuthRequired:        true,
			SimulationSupported: meta.SimulationAvailable,
			Confirm:             meta.Class.RequiresConfirmation(),
			Reversible:          meta.Reversible,
			ChangesState:        meta.Class.AffectsTargetEnvironment(),
			Targets:             targets,
			Duration:            duration,
			HardwareCapability:  hardwareCapabilityFor(meta),
			Schema: Schema{
				Input: inputs,
				Output: []OutputField{
					{Name: "operation", Type: "OperationRecord", Description: "the recorded run, including status, frames transmitted, cleanup state, and evidence"},
					{Name: "findings", Type: "[]Finding"},
					{Name: "evidence", Type: "[]Evidence"},
				},
			},
		})
	}
	return tools
}

// hardwareCapabilityFor names the runtime capability that answers whether a
// host can run an operation module.
//
// It is derived from what the module declares rather than asserted beside it, so
// the published hardware claim cannot contradict the module's own declaration.
//
// Transmit is checked first because it is the requirement that actually refuses
// a run: a host that cannot write frames fails every transmitting module
// whatever its monitor-mode state is. A module scoped to a Bluetooth adapter
// needs the adapter, since it queries the controller. Anything else operates on
// a capture, a session, or a saved file and needs no radio at all, which is
// reported as empty rather than guessed at from the domain: two of the BLE
// modules review recorded data, and calling them radio-dependent would have
// claimed a dependency they do not have.
func hardwareCapabilityFor(meta operation.Meta) string {
	for _, requirement := range meta.RequiredHardware {
		switch requirement {
		case operation.HardwareRawTransmit:
			return models.HardwareWiFiFrameInjection
		case operation.HardwareMonitorMode:
			return models.HardwareWiFiMonitorMode
		}
	}
	for _, targetType := range meta.TargetTypes {
		if targetType == models.TargetBluetoothAdapter {
			return models.HardwareBluetoothAdapterDiscovery
		}
	}
	return ""
}

func joinPhrases(phrases []string) string {
	switch len(phrases) {
	case 0:
		return ""
	case 1:
		return phrases[0]
	case 2:
		return phrases[0] + " and " + phrases[1]
	default:
		out := ""
		for i, phrase := range phrases[:len(phrases)-1] {
			if i > 0 {
				out += ", "
			}
			out += phrase
		}
		return out + ", and " + phrases[len(phrases)-1]
	}
}
