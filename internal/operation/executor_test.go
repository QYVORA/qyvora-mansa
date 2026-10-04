package operation

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/QYVORA/qyvora-mansa/internal/transport"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// stubBackend is a provider that answers the questions the gates ask without
// touching any hardware.
type stubBackend struct {
	name         string
	capabilities []string
	writable     bool
	probeErr     error
	linkType     uint32
}

func (b *stubBackend) Name() string { return b.name }

func (b *stubBackend) DiscoverInterfaces() ([]models.WirelessInterface, error) {
	return []models.WirelessInterface{{Name: "wlan0"}}, nil
}

func (b *stubBackend) Scan(context.Context, string, int) ([]models.AccessPoint, []models.Station, error) {
	return nil, nil, nil
}

func (b *stubBackend) Observe(context.Context, string) ([]models.TrafficObservation, error) {
	return nil, nil
}

func (b *stubBackend) Supported() bool { return true }

func (b *stubBackend) Capabilities() []string { return b.capabilities }

func (b *stubBackend) ProbeTransmit(string) (models.TransmitCapability, error) {
	if b.probeErr != nil {
		return models.TransmitCapability{}, b.probeErr
	}
	return models.TransmitCapability{
		Interface: "wlan0", Writable: b.writable,
		WritableReason: "the stub reports a writable interface",
	}, nil
}

func (b *stubBackend) TransmitLinkType(string) (uint32, error) { return b.linkType, nil }

func (b *stubBackend) Transmit(_ context.Context, _ string, frames [][]byte) (transport.TransmitStats, error) {
	var stats transport.TransmitStats
	for _, frame := range frames {
		stats.Frames++
		stats.Bytes += uint64(len(frame))
	}
	return stats, nil
}

// transmitModule declares everything the gates check, so each test spoils
// exactly one gate.
func transmitModule() Module { return &stubGateModule{meta: gateMeta()} }

func gateMeta() Meta {
	return Meta{
		ID:                  "wifi.test.gate",
		Title:               "Gate Probe",
		Description:         "Proves the gates refuse what they should.",
		Domain:              "wifi",
		Class:               models.ClassActiveTest,
		Risk:                "medium",
		SimulationAvailable: true,
		MaxDuration:         30 * time.Second,
		MaxFrames:           8,
		Parameters: []Parameter{
			{Name: "station", Kind: "mac", Required: true},
			{Name: LabParameterForTest, Kind: "bool", Required: true},
		},
		TargetTypes:      []models.TargetType{models.TargetBSSID},
		RequiredHardware: []string{HardwareMonitorMode, HardwareRawTransmit},
		Limitations:      []string{"a test"},
	}
}

// LabParameterForTest mirrors exploitation.LabParameter, which this package
// must not import.
const LabParameterForTest = "lab"

type stubGateModule struct {
	meta     Meta
	ran      bool
	runError error
}

func (m *stubGateModule) Meta() Meta { return m.meta }

func (m *stubGateModule) Run(context.Context, *Execution) (Outcome, error) {
	m.ran = true
	if m.runError != nil {
		return Outcome{}, m.runError
	}
	return Outcome{}, nil
}

func bssidTarget(value string, authorized bool) *models.Target {
	return &models.Target{
		Type: models.TargetBSSID, Value: value,
		Authorization: models.Authorization{Granted: authorized},
	}
}

func validRequest() Request {
	return Request{
		ModuleID:  "wifi.test.gate",
		Class:     models.ClassActiveTest,
		Target:    bssidTarget("00:11:22:33:44:55", true),
		Interface: "wlan0",
		Params:    map[string]string{"station": "aa:bb:cc:dd:ee:ff", LabParameterForTest: ""},
		DryRun:    true,
	}
}

func newTestExecutor(t *testing.T, module Module, backend transport.Backend) *Executor {
	t.Helper()
	registry := NewRegistry()
	if err := registry.Register(module); err != nil {
		t.Fatalf("register: %v", err)
	}
	return &Executor{
		Registry: registry,
		Backend:  backend,
		Now:      func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
	}
}

// A writable, correctly declared module must actually run, so the refusal tests
// below are testing refusals rather than a module that never works.
func TestExecutorRunsAGateSatisfyingRequest(t *testing.T) {
	module := &stubGateModule{meta: gateMeta()}
	ex := newTestExecutor(t, module, &stubBackend{name: "stub", writable: true, linkType: 127})

	req := validRequest()
	req.DryRun = false
	if _, err := ex.Execute(context.Background(), req); err != nil {
		t.Fatalf("a request that satisfies every gate must run: %v", err)
	}
	if !module.ran {
		t.Fatal("the module was not run")
	}
}

// An unresolvable module has no declaration, so there is nothing to build a
// record from. The error must still name what was asked for.
func TestUnresolvableModuleIsNamedInTheError(t *testing.T) {
	ex := newTestExecutor(t, &stubGateModule{meta: gateMeta()}, &stubBackend{name: "stub", writable: true})

	req := validRequest()
	req.ModuleID = "wifi.test.absent"
	record, err := ex.Execute(context.Background(), req)
	if err == nil {
		t.Fatal("an unknown module must not run")
	}
	if !strings.Contains(err.Error(), "wifi.test.absent") {
		t.Fatalf("error = %q, want it to name the module that was asked for", err)
	}
	if record.ModuleID != "" {
		t.Fatalf("no record may be invented for an unresolvable module: %+v", record)
	}
}

func TestExecutorRefusesAtEachGate(t *testing.T) {
	tests := []struct {
		name     string
		writable bool
		noSim    bool
		spoof    func(*Request)
		wantGate string
	}{
		{
			// A validation module must not be reachable through `exploit`, or it
			// would inherit exploit gates while keeping validation's behavior.
			name:     "class mismatch",
			writable: true,
			spoof:    func(r *Request) { r.Class = models.ClassExploitation },
			wantGate: "resolution",
		},
		{
			name:     "undeclared parameter",
			writable: true,
			spoof:    func(r *Request) { r.Params["typo"] = "1" },
			wantGate: "parameters",
		},
		{
			name:     "missing required parameter",
			writable: true,
			spoof:    func(r *Request) { delete(r.Params, "station") },
			wantGate: "parameters",
		},
		{
			// A valueless flag-style parameter arrives as an empty string, which
			// is how `--param lab` is supplied. Treating that as missing would
			// make the acknowledgement impossible to give.
			name:     "valueless bool parameter is supplied",
			writable: true,
			wantGate: "",
		},
		{
			name:     "no target",
			writable: true,
			spoof:    func(r *Request) { r.Target = nil },
			wantGate: "target",
		},
		{
			// Authorization is scope, not a formality.
			name:     "unauthorized target",
			writable: true,
			spoof: func(r *Request) {
				r.Target = bssidTarget("00:11:22:33:44:55", false)
			},
			wantGate: "authorization",
		},
		{
			name:     "target of the wrong type",
			writable: true,
			spoof: func(r *Request) {
				r.Target = &models.Target{
					Type: models.TargetInterface, Value: "wlan0",
					Authorization: models.Authorization{Granted: true},
				}
			},
			wantGate: "scope",
		},
		{
			// Without a simulation path a fixture result would be reported as an
			// observation of the real target.
			name:     "simulated run of a module with no simulation path",
			writable: true,
			noSim:    true,
			spoof:    func(r *Request) { r.Simulated = true },
			wantGate: "simulation",
		},
		{
			// The decisive refusal: a module that needs to transmit, on a
			// provider that cannot write, must be `unavailable` and must never
			// be downgraded to a simulated run.
			name:     "provider cannot transmit",
			writable: false,
			wantGate: "hardware",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			meta := gateMeta()
			if test.noSim {
				meta.SimulationAvailable = false
			}
			module := &stubGateModule{meta: meta}
			backend := &stubBackend{name: "stub", writable: test.writable, linkType: 127}
			ex := newTestExecutor(t, module, backend)

			req := validRequest()
			if test.spoof != nil {
				test.spoof(&req)
			}

			_, err := ex.Execute(context.Background(), req)
			if test.wantGate == "" {
				// The control case: this must succeed.
				if err != nil {
					t.Fatalf("this request must be accepted: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected a refusal")
			}
			var refusal *RefusalError
			if !errors.As(err, &refusal) {
				t.Fatalf("error = %v, want a refusal carrying its gate", err)
			}
			if refusal.Gate != test.wantGate {
				t.Fatalf("gate = %q, want %q (reason: %s)", refusal.Gate, test.wantGate, refusal.Reason)
			}
			if refusal.Reason == "" {
				t.Fatal("a refusal must explain itself")
			}
			if module.ran {
				t.Fatal("a refused request must not reach the module")
			}
		})
	}
}

// A refusal must be a refusal, not a pass with a warning.
func TestUnwritableProviderNeverReportsSuccess(t *testing.T) {
	module := &stubGateModule{meta: gateMeta()}
	ex := newTestExecutor(t, module, &stubBackend{name: "stub", writable: false, linkType: 127})

	req := validRequest()
	req.DryRun = false
	record, err := ex.Execute(context.Background(), req)
	if err == nil {
		t.Fatalf("a run against an unwritable provider must not succeed: %+v", record)
	}
	if record.Status == models.StatusCompleted {
		t.Fatalf("status must not be a completion: %+v", record.Status)
	}
	if module.ran {
		t.Fatal("the module must not run when the provider cannot transmit")
	}
}

// The provider's own reason must survive into the refusal, because "unavailable"
// without a cause is the least actionable thing a tool can say.
func TestTransmitRefusalCarriesTheProviderReason(t *testing.T) {
	module := &stubGateModule{meta: gateMeta()}
	backend := &stubBackend{name: "stub", writable: false, probeErr: errors.New("CAP_NET_RAW is required")}
	ex := newTestExecutor(t, module, backend)

	req := validRequest()
	req.DryRun = false
	_, err := ex.Execute(context.Background(), req)
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if !strings.Contains(err.Error(), "CAP_NET_RAW") {
		t.Fatalf("error = %q, want the provider's reason to survive", err)
	}
}

// A dry run plans the frames but transmits nothing. It still surfaces the
// hardware gate, because a plan that reads as executable when the provider
// cannot write is the misleading half of this pair.
func TestDryRunPlansWithoutTransmitting(t *testing.T) {
	module := &stubGateModule{meta: gateMeta()}
	ex := newTestExecutor(t, module, &stubBackend{name: "stub", writable: true, linkType: 127})

	record, err := ex.Execute(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("a dry run must plan: %v", err)
	}
	if record.Status != models.StatusPlanned {
		t.Fatalf("status = %q, want a plan rather than a run", record.Status)
	}
	if module.ran {
		t.Fatal("a dry run must not execute the module")
	}
	if record.FramesTransmitted != 0 {
		t.Fatalf("a dry run reported %d frames transmitted", record.FramesTransmitted)
	}
}

// A plan against a provider that cannot write is `unavailable`, not `planned`:
// the operator asked what would happen here, and here it would not happen.
func TestDryRunReportsTheHardwareGateItWouldHit(t *testing.T) {
	module := &stubGateModule{meta: gateMeta()}
	ex := newTestExecutor(t, module, &stubBackend{name: "stub", writable: false})

	record, err := ex.Execute(context.Background(), validRequest())
	if err == nil {
		t.Fatal("a plan that could not be executed must not read as executable")
	}
	if record.Status != models.StatusUnavailable {
		t.Fatalf("status = %q, want unavailable", record.Status)
	}
	if module.ran {
		t.Fatal("a dry run must not execute the module")
	}
}

// Confirmation is asked only for classes that affect the target's environment,
// and only after the cheaper gates have passed.
func TestConfirmationIsAskedLastAndOnlyWhenItMatters(t *testing.T) {
	meta := gateMeta()
	meta.Class = models.ClassExploitation
	meta.SimulationAvailable = true
	module := &stubGateModule{meta: meta}

	var asked int
	ex := newTestExecutor(t, module, &stubBackend{name: "stub", writable: true, linkType: 127})
	ex.Confirm = func(Meta, Request) error { asked++; return nil }

	req := validRequest()
	req.Class = models.ClassExploitation
	req.DryRun = false
	if _, err := ex.Execute(context.Background(), req); err != nil {
		t.Fatalf("run: %v", err)
	}
	if asked != 1 {
		t.Fatalf("confirmation asked %d time(s), want 1", asked)
	}

	// A cheaper gate must refuse before the operator is asked to approve.
	asked = 0
	broken := validRequest()
	broken.Class = models.ClassExploitation
	broken.Target = bssidTarget("00:11:22:33:44:55", false)
	if _, err := ex.Execute(context.Background(), broken); err == nil {
		t.Fatal("an unauthorized target must be refused")
	}
	if asked != 0 {
		t.Fatalf("confirmation was asked %d time(s) for a run that was going to be refused", asked)
	}
}
