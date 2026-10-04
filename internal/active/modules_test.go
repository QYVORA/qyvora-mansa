package active

import (
	"strings"
	"testing"
	"time"

	"github.com/QYVORA/qyvora-mansa/internal/operation"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// allModules returns the six validation and active-test modules this package
// ships, so the contract below is checked against what is actually wired in
// rather than a list written separately.
func allModules() []operation.Module {
	return append(BluetoothModules(), WiFiModules()...)
}

func TestEveryModuleCarriesAnHonestDeclaration(t *testing.T) {
	for _, module := range allModules() {
		meta := module.Meta()

		if !strings.Contains(meta.ID, ".") {
			t.Errorf("%q is not a dotted identifier", meta.ID)
		}
		if meta.Title == "" || meta.Description == "" {
			t.Errorf("%s has no title or description", meta.ID)
		}
		// A module that is silent about its limits is the one most likely to be
		// read as proving more than it did.
		if len(meta.Limitations) == 0 {
			t.Errorf("%s states no limitation", meta.ID)
		}
		if len(meta.Prerequisites) == 0 {
			t.Errorf("%s states no prerequisite", meta.ID)
		}
		// Without a bound a run could overrun, and the executor cannot cap what
		// the module itself does not limit.
		if meta.MaxDuration <= 0 {
			t.Errorf("%s declares no duration ceiling", meta.ID)
		}
		// A frame ceiling only means something for a module that sends frames.
		if meta.HasHardware(operation.HardwareRawTransmit) && meta.MaxFrames <= 0 {
			t.Errorf("%s transmits but declares no frame ceiling", meta.ID)
		}
		if !meta.HasHardware(operation.HardwareRawTransmit) && meta.MaxFrames > 0 {
			t.Errorf("%s declares a frame ceiling but sends no frames", meta.ID)
		}
		if len(meta.TargetTypes) == 0 {
			t.Errorf("%s accepts no target type", meta.ID)
		}
		// A validation module is reversible in the sense that it changes nothing;
		// an active test that sends frames is not, and must say so.
		if meta.Class == models.ClassActiveTest && meta.Reversible {
			t.Errorf("%s transmits frames but declares itself reversible", meta.ID)
		}
		// A passive module changes nothing, so saying so is accurate rather than
		// an overclaim.
		if meta.Class == models.ClassValidation && !meta.Reversible {
			t.Errorf("%s changes nothing, so it can state that it is reversible", meta.ID)
		}
	}
}

// Nothing in this package may be declared to need hardware it cannot check, and
// nothing may claim a hardware requirement without naming one of the executor's
// known requirements.
func TestHardwareRequirementsAreKnown(t *testing.T) {
	known := map[string]bool{
		operation.HardwareMonitorMode: true,
		operation.HardwareRawTransmit: true,
	}
	for _, module := range allModules() {
		meta := module.Meta()
		for _, requirement := range meta.RequiredHardware {
			if !known[requirement] {
				t.Errorf("%s requires unknown hardware %q", meta.ID, requirement)
			}
		}
	}
}

// A module that transmits must declare the transmit requirement, or the
// executor would let it run against a provider that cannot write.
func TestTransmittingModulesDeclareRawTransmit(t *testing.T) {
	for _, module := range allModules() {
		meta := module.Meta()
		if meta.Class == models.ClassActiveTest && !meta.HasHardware(operation.HardwareRawTransmit) {
			t.Errorf("%s declares a frame ceiling but does not require raw transmit", meta.ID)
		}
	}
}

func TestIdentifiersAreDistinct(t *testing.T) {
	seen := map[string]string{}
	for _, module := range allModules() {
		meta := module.Meta()
		if previous, clash := seen[meta.ID]; clash {
			t.Errorf("identifier %q is used by both %s and %s", meta.ID, previous, meta.Title)
		}
		seen[meta.ID] = meta.Title
	}
	if len(seen) != 6 {
		t.Fatalf("registered %d distinct modules, want 6", len(seen))
	}
}

// Every module must be reachable by the identifiers the contract publishes.
func TestPublishedModuleIdentifiersAreTheOnesRegistered(t *testing.T) {
	registered := map[string]bool{}
	for _, module := range allModules() {
		registered[module.Meta().ID] = true
	}
	for _, id := range []string{
		ModuleBLEAdapterCapabilities,
		ModuleBLEAdvertisingExposure,
		ModuleBLEGATTAccessControl,
		ModuleWiFiInjectVerify,
		ModuleWiFiManagementProtection,
		ModuleWiFiAuthenticationProbe,
	} {
		if !registered[id] {
			t.Errorf("published identifier %q is not registered", id)
		}
	}
}

// The BLE modules read the adapter rather than sending frames, so they must not
// declare a transmit requirement: a run that only reads must not be refused
// because the host cannot write.
func TestBluetoothModulesArePassive(t *testing.T) {
	for _, module := range BluetoothModules() {
		meta := module.Meta()
		if meta.Domain != "bluetooth" {
			t.Errorf("%s declares domain %q, want bluetooth", meta.ID, meta.Domain)
		}
		if meta.HasHardware(operation.HardwareRawTransmit) {
			t.Errorf("%s declares raw transmit but never sends a frame", meta.ID)
		}
		if meta.Class != models.ClassValidation {
			t.Errorf("%s declares class %q, want validation", meta.ID, meta.Class)
		}
		if !meta.SimulationAvailable {
			t.Errorf("%s declares no simulation path", meta.ID)
		}
	}
}

// The WiFi active tests send frames and must be declared reversible=no, because
// a frame already on the air cannot be recalled.
func TestWiFiActiveModulesAreIrreversible(t *testing.T) {
	for _, module := range WiFiModules() {
		meta := module.Meta()
		if meta.Class != models.ClassActiveTest {
			t.Errorf("%s declares class %q, want active_test", meta.ID, meta.Class)
		}
		if meta.Reversible {
			t.Errorf("%s claims to be reversible", meta.ID)
		}
		if meta.MaxFrames > 64 {
			t.Errorf("%s allows %d frames, well above a bounded probe", meta.ID, meta.MaxFrames)
		}
		if meta.MaxDuration > 2*time.Minute {
			t.Errorf("%s allows %s, longer than a bounded probe should need", meta.ID, meta.MaxDuration)
		}
	}
}
