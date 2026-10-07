// Package active holds the validation and active-test operation modules.
//
// The two classes live together because they share a rule: neither may claim
// more than it observed. A validation module reviews data already collected and
// an active test reports what a target actually answered, and both refuse to
// turn silence into a negative result.
package active

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-mansa/internal/bluetooth"
	"github.com/QYVORA/qyvora-mansa/internal/operation"
	"github.com/QYVORA/qyvora-mansa/internal/transport"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// ModuleIDs are the identifiers this package registers. They are constants
// because the capability contract, the CLI, and the tests all name them, and a
// renamed module must fail to compile rather than silently disappear from the
// published contract.
const (
	ModuleBLEAdapterCapabilities   = "ble.adapter.capabilities"
	ModuleBLEAdvertisingExposure   = "ble.advertising.exposure"
	ModuleBLEGATTAccessControl     = "ble.gatt.access.control"
	ModuleWiFiInjectVerify         = "wifi.inject.verify"
	ModuleWiFiManagementProtection = "wifi.management.protection.probe"
	ModuleWiFiAuthenticationProbe  = "wifi.authentication.probe"
)

// ControllerInfoProvider is the read-only HCI controller metadata path. It is
// satisfied by both the real Linux provider and the simulation fixture, which is
// what lets one module serve a live and a simulated run.
type ControllerInfoProvider interface {
	ControllerInfo(ctx context.Context, adapter string) (models.BluetoothControllerInfo, error)
}

// BluetoothModules returns the BLE validation modules.
//
// None of them emits radio traffic: each reviews data already collected or
// already recorded by the controller. A validation module that transmitted
// would no longer be the smallest interaction that can answer the question.
func BluetoothModules() []operation.Module {
	return []operation.Module{
		&adapterCapabilities{},
		&advertisingExposure{},
		&gattAccessControl{},
	}
}

// adapterCapabilities reports what a controller says about itself.
//
// It uses read-only HCI commands only: no scan is enabled, no connection is
// attempted, and no power state is changed. Everything it reports is a
// controller statement, never an inference from a device seen on the air.
type adapterCapabilities struct{}

func (m *adapterCapabilities) Meta() operation.Meta {
	return operation.Meta{
		ID:          ModuleBLEAdapterCapabilities,
		Title:       "BLE Adapter Capabilities",
		Description: "Report the controller version, address, supported commands, LE features, and LE buffer size using read-only HCI commands.",
		Domain:      "bluetooth",
		Class:       models.ClassValidation,
		// Passive noise: reads local controller metadata using HCI commands; no
		// transmission or observable behavior.
		NoiseLevel: models.NoiseLevelPassive,
		Risk:       "low",
		Reversible: true,
		// The fixture answers from recorded controller metadata, so a simulated
		// run exercises the reporting path without an adapter.
		SimulationAvailable: true,
		MaxDuration:         30 * time.Second,
		TargetTypes:         []models.TargetType{models.TargetBluetoothAdapter},
		Parameters: []operation.Parameter{
			{Name: "adapter", Kind: "string", Description: "HCI adapter name such as hci0; defaults to the request target", Default: "hci0"},
		},
		Prerequisites: []string{
			"A Bluetooth HCI adapter is present.",
			"The process may open the adapter's HCI device node.",
		},
		Limitations: []string{
			"Controller capabilities are what the adapter reports about itself; they do not describe any paired, connected, or nearby device.",
			"An adapter that does not answer a read-only command is reported as unreadable rather than as lacking the capability.",
		},
	}
}

func (m *adapterCapabilities) Run(ctx context.Context, ex *operation.Execution) (operation.Outcome, error) {
	meta := m.Meta()
	adapter := ex.Request.Param(meta, "adapter")
	if adapter == "" {
		adapter = adapterName(ex.Request)
	}
	provider, ok := ex.Backend.(ControllerInfoProvider)
	if !ok {
		return operation.Outcome{}, fmt.Errorf("provider %s cannot report Bluetooth controller information", ex.Backend.Name())
	}
	info, err := provider.ControllerInfo(ctx, adapter)
	if err != nil {
		return operation.Outcome{}, fmt.Errorf("read %s controller information: %w", adapter, err)
	}

	outcome := operation.Outcome{
		Notes: []string{
			fmt.Sprintf("Controller %s reports HCI version %s.", adapter, info.HCIVersionName),
		},
		Limitations: meta.Limitations,
		References:  []string{"Bluetooth Core Specification, Version 6.0, Volume 4: Controller"},
	}
	if info.Address != "" {
		outcome.Notes = append(outcome.Notes, fmt.Sprintf("Controller address %s.", info.Address))
	}
	if len(info.LEFeatures) > 0 {
		outcome.Notes = append(outcome.Notes,
			fmt.Sprintf("Controller reports %d LE feature(s): %s.", len(info.LEFeatures), strings.Join(info.LEFeatures, ", ")))
	}
	if info.LEBufferLength > 0 {
		outcome.Notes = append(outcome.Notes,
			fmt.Sprintf("Controller reports an LE buffer length of %d byte(s) and %d LE ACL packet(s).", info.LEBufferLength, info.LEPackets))
	}
	if info.SupportedCommandsHex != "" {
		outcome.Notes = append(outcome.Notes, "Controller reported its 64-octet supported-command bitmap.")
	}
	if len(info.Unreadable) > 0 {
		// An unread field is stated, not inferred. Reporting an absent field as
		// absent capability would turn a permissions problem into a finding.
		outcome.Notes = append(outcome.Notes,
			fmt.Sprintf("Controller did not answer %d read-only query/queries: %s.", len(info.Unreadable), strings.Join(info.Unreadable, ", ")))
		outcome.Limitations = append(outcome.Limitations,
			"Some controller queries were unreadable, so this record does not describe the whole capability set.")
	}
	if info.Simulated {
		outcome.Notes = append(outcome.Notes, "Controller information came from the simulation fixture, not from hardware.")
		outcome.Limitations = append(outcome.Limitations,
			"Simulated controller metadata demonstrates the reporting path and describes no real adapter.")
	}

	outcome.Evidence = append(outcome.Evidence, models.Evidence{
		ID:     models.NewID("evidence"),
		Kind:   models.EvidenceConfig,
		Source: "hci-read-only-commands",
		Target: adapter,
		Detail: fmt.Sprintf("HCI version %s; LE buffer length %d; %d LE feature(s); supported commands %s",
			info.HCIVersionName, info.LEBufferLength, len(info.LEFeatures),
			orNone(info.SupportedCommandsHex)),
	})
	return outcome, nil
}

// advertisingExposure reviews collected advertisements for the identifiers that
// make a device trackable.
//
// It reads a session or nothing: it never scans. A scanning validation module
// would emit traffic and turn a low-risk review into an active test.
type advertisingExposure struct{}

func (m *advertisingExposure) Meta() operation.Meta {
	return operation.Meta{
		ID:          ModuleBLEAdvertisingExposure,
		Title:       "BLE Advertising Exposure",
		Description: "Review collected BLE advertisements for local names, service UUIDs, TX power, and manufacturer data that support tracking.",
		Domain:      "bluetooth",
		Class:       models.ClassValidation,
		// Passive noise: analyzes previously collected data; no new transmission.
		NoiseLevel: models.NoiseLevelPassive,
		Risk:       "low",
		Reversible: true,
		// The fixture supplies a deterministic advertisement set, so the review
		// path is exercised without scanning.
		SimulationAvailable: true,
		MaxDuration:         30 * time.Second,
		TargetTypes:         []models.TargetType{models.TargetSession},
		Parameters: []operation.Parameter{
			{Name: "min_service_uuids", Kind: "int", Description: "service UUIDs at which advertising is treated as identifying", Default: "1"},
		},
		Prerequisites: []string{
			"Advertising reports have been collected into the session being reviewed.",
		},
		Limitations: []string{
			"Advertising data is only as identifying as what the device chooses to broadcast; absence of an identifier here is not evidence that a device transmits none.",
			"A review of collected advertisements says nothing about what a device advertises on channels or in intervals not captured.",
		},
	}
}

func (m *advertisingExposure) Run(_ context.Context, ex *operation.Execution) (operation.Outcome, error) {
	meta := m.Meta()
	threshold, err := ex.Request.IntParam(meta, "min_service_uuids")
	if err != nil {
		return operation.Outcome{}, err
	}
	if threshold < 1 {
		return operation.Outcome{}, fmt.Errorf("parameter %q must be at least 1, got %d", "min_service_uuids", threshold)
	}

	devices := collectedDevices(ex)
	if ex.Request.Simulated {
		devices = simulatedDevices()
	}
	if len(devices) == 0 {
		// No data is reported as no data. It is not reported as "no exposure":
		// a scan that collected nothing and a scan that was never run look the
		// same here.
		return operation.Outcome{
			Notes: []string{"No BLE advertisements were available to review; no exposure conclusion is drawn."},
			Limitations: append(meta.Limitations,
				"No advertisements were supplied, so nothing was reviewed and nothing was refuted."),
		}, nil
	}

	var tracked []models.BluetoothDeviceObservation
	for _, device := range devices {
		if isTrackable(device.Advertisement, threshold) {
			tracked = append(tracked, device)
		}
	}

	outcome := operation.Outcome{
		Notes:       []string{fmt.Sprintf("Reviewed %d collected BLE advertisement(s); %d carried tracking-supporting identifiers.", len(devices), len(tracked))},
		Limitations: meta.Limitations,
		References:  []string{"Bluetooth Core Specification, Version 6.0, Volume 3, Part C, Chapter 11: Advertising"},
	}

	for _, device := range tracked {
		identifiers := describeIdentifiers(device.Advertisement)
		outcome.Evidence = append(outcome.Evidence, models.Evidence{
			ID:     models.NewID("evidence"),
			Kind:   models.EvidenceObservation,
			Source: "ble-advertising",
			Target: device.Address,
			Detail: identifiers,
		})
	}

	if len(tracked) == 0 {
		outcome.Limitations = append(outcome.Limitations,
			"No reviewed advertisement carried a tracking-supporting identifier. This does not establish that the devices broadcast none outside the reviewed data.")
		return outcome, nil
	}

	finding := models.Finding{
		ID:          models.NewID("finding"),
		RuleID:      "BLE-001",
		Title:       "BLE advertising carries tracking-supporting identifiers",
		Category:    "bluetooth",
		Severity:    models.SeverityLow,
		Confidence:  models.ConfObserved,
		Description: fmt.Sprintf("%d of %d reviewed BLE advertisements carried a local name, service UUID, or manufacturer identifier that a passive observer could use to recognize the device again.", len(tracked), len(devices)),
		Target:      ex.Request.Target.DisplayName(),
		Status:      models.FindingDetected,
		// The recommendation is about the reviewed data, not a demand that a
		// device stop identifying itself.
		Recommendation: "Where a device does not need to broadcast an identifying name, service UUID, or manufacturer payload, suppress it in its advertising configuration.",
		Evidence:       outcome.Evidence,
		References:     outcome.References,
		Timestamp:      nowOf(ex),
	}
	outcome.Findings = []models.Finding{finding}
	return outcome, nil
}

// gattAccessControl reviews a saved attribute table for writable
// characteristics with no reported write protection.
//
// It reviews a saved table and nothing else. Live GATT enumeration would connect
// to the device, which is not the smallest interaction that can answer the
// question.
type gattAccessControl struct{}

func (m *gattAccessControl) Meta() operation.Meta {
	return operation.Meta{
		ID:          ModuleBLEGATTAccessControl,
		Title:       "BLE GATT Access Control",
		Description: "Review a saved GATT attribute table for writable characteristics with no reported encryption, authentication, or authorization requirement.",
		Domain:      "bluetooth",
		Class:       models.ClassValidation,
		// Passive noise: analyzes previously saved GATT database; no device
		// interaction.
		NoiseLevel: models.NoiseLevelPassive,
		Risk:       "low",
		Reversible: true,
		// The fixture supplies a deterministic attribute table, so the review is
		// exercisable without a device.
		SimulationAvailable: true,
		MaxDuration:         30 * time.Second,
		TargetTypes:         []models.TargetType{models.TargetCapture, models.TargetSession},
		Parameters: []operation.Parameter{
			{Name: "database", Kind: "path", Description: "saved GATT attribute table JSON; defaults to the request database"},
		},
		Prerequisites: []string{
			"A GATT attribute table has been recorded and supplied to the run.",
		},
		Limitations: []string{
			"An attribute reported without write protection is not proven reachable by an unauthenticated client: the application layer may still require pairing or a connection policy the attribute table does not show.",
			"The review covers only the attributes in the supplied table; characteristics the table omits are not assessed.",
		},
	}
}

func (m *gattAccessControl) Run(_ context.Context, ex *operation.Execution) (operation.Outcome, error) {
	meta := m.Meta()
	path := ex.Database
	if path == "" {
		path = ex.Request.Param(meta, "database")
	}
	database, simulated, err := loadDatabase(path, ex)
	if err != nil {
		return operation.Outcome{}, err
	}

	verdicts := bluetooth.GATTAccessVerdicts(database)
	outcome := operation.Outcome{
		Notes: []string{fmt.Sprintf("Reviewed a GATT attribute table for %s: %d service(s), %d characteristic(s), %d writable without reported protection.",
			database.DeviceAddress, countServices(database), countCharacteristics(database), len(verdicts))},
		Limitations: meta.Limitations,
		References:  []string{"Bluetooth Core Specification, Version 6.0, Volume 3, Part F: Attribute Server"},
	}
	if simulated {
		outcome.Notes = append(outcome.Notes, "The attribute table came from the simulation fixture, not from a device.")
		outcome.Limitations = append(outcome.Limitations,
			"A simulated attribute table demonstrates the review path and describes no real device.")
	}

	findings := bluetooth.AnalyzeGATT(database)
	for index := range findings {
		findings[index].Target = database.DeviceAddress
	}
	outcome.Findings = findings
	outcome.Evidence = findingsEvidence(findings)
	if len(findings) == 0 {
		outcome.Notes = append(outcome.Notes,
			"No writable characteristic without a reported write protection requirement was found in this table.")
		outcome.Limitations = append(outcome.Limitations,
			"No writable characteristic without reported protection was found; this refutes the condition for the reviewed table only, not for attributes the table omits.")
	}
	return outcome, nil
}

// isTrackable reports whether an advertisement carries an identifier a passive
// observer could use to recognize the device again.
func isTrackable(advertisement models.BLEAdvertisement, serviceThreshold int) bool {
	if advertisement.Name != "" {
		return true
	}
	if len(advertisement.ServiceUUIDs) >= serviceThreshold {
		return true
	}
	// A company identifier plus payload is what makes manufacturer data
	// distinguishing; the company alone is shared by many devices.
	for _, payload := range advertisement.ManufacturerData {
		if len(payload) > 0 {
			return true
		}
	}
	return false
}

// describeIdentifiers renders the tracking-supporting parts of an advertisement.
func describeIdentifiers(advertisement models.BLEAdvertisement) string {
	var parts []string
	if advertisement.Name != "" {
		parts = append(parts, fmt.Sprintf("local name %q", advertisement.Name))
	}
	if len(advertisement.ServiceUUIDs) > 0 {
		sort.Strings(advertisement.ServiceUUIDs)
		parts = append(parts, fmt.Sprintf("service UUID(s) %s", strings.Join(advertisement.ServiceUUIDs, ", ")))
	}
	if len(advertisement.ManufacturerData) > 0 {
		companies := make([]string, 0, len(advertisement.ManufacturerData))
		for company := range advertisement.ManufacturerData {
			companies = append(companies, fmt.Sprintf("0x%04x", company))
		}
		sort.Strings(companies)
		parts = append(parts, fmt.Sprintf("manufacturer data from %s", strings.Join(companies, ", ")))
	}
	if advertisement.TxPower != nil {
		parts = append(parts, fmt.Sprintf("TX power %d dBm", *advertisement.TxPower))
	}
	if len(parts) == 0 {
		return "no tracking-supporting identifier decoded"
	}
	return strings.Join(parts, "; ")
}

// collectedDevices returns the BLE observations available to a validation run.
func collectedDevices(ex *operation.Execution) []models.BluetoothDeviceObservation {
	if ex.Session != nil && len(ex.Session.BluetoothDevices) > 0 {
		return ex.Session.BluetoothDevices
	}
	if ex.Backend == nil {
		return nil
	}
	provider, ok := ex.Backend.(transport.BLEScanProvider)
	if !ok {
		return nil
	}
	// A validation module reads only; the fixture provider returns its
	// deterministic set without transmitting, and a live provider is not asked
	// to scan here.
	if ex.Request.Simulated {
		var devices []models.BluetoothDeviceObservation
		_, err := provider.ScanBLE(context.Background(), "sim0", func(observation models.BluetoothDeviceObservation) error {
			devices = append(devices, observation)
			return nil
		})
		if err != nil {
			return nil
		}
		return devices
	}
	return nil
}

// simulatedDevices returns the fixture advertisement set.
func simulatedDevices() []models.BluetoothDeviceObservation {
	observations, err := bluetooth.ParseLEAdvertisingReports(bluetooth.SimulatedLEAdvertisingReport())
	if err != nil {
		return nil
	}
	return observations
}

// loadDatabase reads a saved attribute table, or returns the fixture under
// simulation. A missing path is an error rather than a silent fixture, because
// reviewing a fixture while the operator believed they reviewed their data is
// the worst available outcome.
func loadDatabase(path string, ex *operation.Execution) (models.GATTDatabase, bool, error) {
	if path == "" {
		if ex.Request.Simulated {
			return bluetooth.SimulatedGATTDatabase(), true, nil
		}
		return models.GATTDatabase{}, false, fmt.Errorf("a saved GATT attribute table is required; supply --database")
	}
	database, err := bluetooth.LoadGATTDatabase(path)
	if err != nil {
		return models.GATTDatabase{}, false, err
	}
	return database, false, nil
}

// findingsEvidence renders a finding's evidence for the operation record.
func findingsEvidence(findings []models.Finding) []models.Evidence {
	var out []models.Evidence
	for _, finding := range findings {
		out = append(out, finding.Evidence...)
	}
	return out
}

func countServices(database models.GATTDatabase) int { return len(database.Services) }

func countCharacteristics(database models.GATTDatabase) int {
	total := 0
	for _, service := range database.Services {
		total += len(service.Characteristics)
	}
	return total
}

func orNone(value string) string {
	if value == "" {
		return "none reported"
	}
	return value
}

// adapterName picks the adapter from the request target when the parameter is
// absent.
func adapterName(request operation.Request) string {
	if request.Target == nil {
		return ""
	}
	return request.Target.Value
}

// nowOf reads the execution clock, falling back to the wall clock.
func nowOf(ex *operation.Execution) time.Time {
	if ex.Now != nil {
		return ex.Now()
	}
	return time.Now()
}
