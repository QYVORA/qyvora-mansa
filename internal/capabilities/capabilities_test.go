package capabilities

import (
	"testing"

	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// knownHardware lists every identifier a provider may report.
//
// The capability contract and the provider reports are joined on these strings
// from different packages, so a capability naming one this list does not know
// would compile and then never match anything. The test states the whole
// vocabulary instead of trusting both sides to stay in step.
var knownHardware = map[string]bool{
	models.HardwareWiFiInterfaceDiscovery:    true,
	models.HardwareWiFiAPEnumeration:         true,
	models.HardwareWiFiClientObservation:     true,
	models.HardwareWiFiRawCapture:            true,
	models.HardwareWiFiKernelPrefilter:       true,
	models.HardwareWiFiFrameInjection:        true,
	models.HardwareWiFiMonitorMode:           true,
	models.HardwareBluetoothAdapterDiscovery: true,
	models.HardwareBluetoothDiscovery:        true,
	models.HardwareBLEDiscovery:              true,
	models.HardwareBLEGATT:                   true,
}

// Every capability must name hardware from the shared vocabulary, or nothing.
func TestHardwareClaimsUseTheSharedVocabulary(t *testing.T) {
	for _, tool := range Registry() {
		if tool.HardwareCapability == "" {
			continue
		}
		if !knownHardware[tool.HardwareCapability] {
			t.Errorf("%s names hardware capability %q, which no provider reports", tool.ID, tool.HardwareCapability)
		}
	}
}

// A tool that reaches the radio must say which radio capability decides it.
// Without this the hardware column would read not_applicable for a scan, which
// is the opposite of the truth.
func TestToolsThatReachTheRadioDeclareTheirHardware(t *testing.T) {
	needsHardware := map[string]string{
		// Scans, live capture, and every transmitting operation.
		"mansa.discover":                               models.HardwareWiFiInterfaceDiscovery,
		"mansa.scan":                                   models.HardwareWiFiAPEnumeration,
		"mansa.enumerate":                              models.HardwareWiFiAPEnumeration,
		"mansa.observe":                                models.HardwareWiFiClientObservation,
		"mansa.capture.live":                           models.HardwareWiFiRawCapture,
		"mansa.bluetooth.adapters":                     models.HardwareBluetoothAdapterDiscovery,
		"mansa.bluetooth.scan":                         models.HardwareBLEDiscovery,
		"mansa.bluetooth.gatt.enumerate":               models.HardwareBLEGATT,
		"mansa.test.wifi.inject.verify":                models.HardwareWiFiFrameInjection,
		"mansa.test.wifi.management.protection.probe":  models.HardwareWiFiFrameInjection,
		"mansa.test.wifi.authentication.probe":         models.HardwareWiFiFrameInjection,
		"mansa.exploit.wifi.management.disruption.lab": models.HardwareWiFiFrameInjection,
		"mansa.exploit.wifi.beacon.spoof.lab":          models.HardwareWiFiFrameInjection,
	}

	byID := map[string]Tool{}
	for _, tool := range Registry() {
		byID[tool.ID] = tool
	}
	for id, want := range needsHardware {
		tool, present := byID[id]
		if !present {
			t.Errorf("%s is not published in the contract", id)
			continue
		}
		if tool.HardwareCapability != want {
			t.Errorf("%s names hardware %q, want %q", id, tool.HardwareCapability, want)
		}
	}
}

// A tool that reads a file, a session, or a report must not claim a radio
// dependency. Calling that unknown would tell an operator their host was
// missing hardware the tool never touches.
func TestOfflineToolsClaimNoHardware(t *testing.T) {
	offline := []string{
		"mansa.analyze",
		"mansa.capture.analyze",
		"mansa.bluetooth.advertisement.parse",
		"mansa.bluetooth.gatt.analyze",
		"mansa.bluetooth.hci.parse",
		"mansa.validate.ble.advertising.exposure",
		"mansa.validate.ble.gatt.access.control",
		"mansa.findings",
		"mansa.evidence",
		"mansa.report",
		"mansa.credentials.verify",
	}
	byID := map[string]Tool{}
	for _, tool := range Registry() {
		byID[tool.ID] = tool
	}
	for _, id := range offline {
		tool, present := byID[id]
		if !present {
			t.Errorf("%s is not published in the contract", id)
			continue
		}
		if tool.HardwareCapability != "" {
			t.Errorf("%s claims hardware %q, but it reads recorded data", id, tool.HardwareCapability)
		}
	}
}

// The derived entries must follow their module's own declaration. Transmit is
// the requirement that actually refuses a run, so it wins over monitor mode.
func TestDerivedToolsFollowTheirModuleDeclaration(t *testing.T) {
	byID := map[string]Tool{}
	for _, tool := range Registry() {
		byID[tool.ID] = tool
	}

	// A module scoped to a Bluetooth adapter queries the controller.
	if got := byID["mansa.validate.ble.adapter.capabilities"].HardwareCapability; got != models.HardwareBluetoothAdapterDiscovery {
		t.Errorf("ble.adapter.capabilities names hardware %q, want adapter discovery", got)
	}
	// Two BLE modules review recorded data, so they claim no radio.
	for _, id := range []string{
		"mansa.validate.ble.advertising.exposure",
		"mansa.validate.ble.gatt.access.control",
	} {
		if got := byID[id].HardwareCapability; got != "" {
			t.Errorf("%s names hardware %q, want none: it reviews recorded data", id, got)
		}
	}
	// Every transmitting module resolves to the transmit capability.
	for _, id := range []string{
		"mansa.test.wifi.inject.verify",
		"mansa.test.wifi.authentication.probe",
		"mansa.test.wifi.management.protection.probe",
		"mansa.exploit.wifi.management.disruption.lab",
		"mansa.exploit.wifi.beacon.spoof.lab",
	} {
		if got := byID[id].HardwareCapability; got != models.HardwareWiFiFrameInjection {
			t.Errorf("%s names hardware %q, want frame injection", id, got)
		}
	}
}

// Every capability the contract publishes must be unique, and every operation
// module must reach the contract: a module the binary provides but the contract
// omits is invisible to anything that consumes the contract.
func TestOperationModulesAllReachTheContract(t *testing.T) {
	seen := map[string]bool{}
	for _, tool := range Registry() {
		if seen[tool.ID] {
			t.Errorf("capability %q is published twice", tool.ID)
		}
		seen[tool.ID] = true
		if tool.ID == "" {
			t.Error("a capability has no id")
		}
		if tool.Name == "" || tool.Description == "" {
			t.Errorf("%s has no name or description", tool.ID)
		}
		if tool.Framework != "mansa" {
			t.Errorf("%s declares framework %q", tool.ID, tool.Framework)
		}
	}
	for _, want := range []string{
		"mansa.validate.ble.adapter.capabilities",
		"mansa.validate.ble.advertising.exposure",
		"mansa.validate.ble.gatt.access.control",
		"mansa.test.wifi.inject.verify",
		"mansa.test.wifi.management.protection.probe",
		"mansa.test.wifi.authentication.probe",
		"mansa.exploit.wifi.management.disruption.lab",
		"mansa.exploit.wifi.beacon.spoof.lab",
		"mansa.bluetooth.gatt.enumerate",
		"mansa.credentials.verify",
	} {
		if !seen[want] {
			t.Errorf("%q is not published in the contract", want)
		}
	}
}
