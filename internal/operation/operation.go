// Package operation defines the module contract shared by Mansa's three
// operation classes and the registry that holds them.
//
// One registry exists on purpose. The CLI resolves a module from it, the
// executor gates it, and the machine-readable capability contract derives its
// published entries from it. A module therefore cannot exist in one surface and
// be missing from another, which is the failure a hand-maintained capability
// list invites: the contract advertises a capability the binary refuses, or
// omits one it will happily run.
//
// A module declares what it is and what it needs. It does not decide whether it
// may run: that is the executor's job, and it is the same job for every class,
// so the gates cannot drift between a validation module and an exploit.
package operation

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-mansa/internal/events"
	"github.com/QYVORA/qyvora-mansa/internal/transport"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// Hardware requirements a module may declare. The names are the contract the
// capability registry publishes, so they are constants rather than strings
// scattered across modules.
const (
	// HardwareMonitorMode requires an interface already in monitor mode. No
	// module changes interface mode: channel and mode belong to the capture
	// command, which restores what it found.
	HardwareMonitorMode = "monitor_mode"

	// HardwareRawTransmit requires an interface that accepts raw frame writes.
	// Satisfying it proves the kernel will queue a write, never that a frame
	// reached the air.
	HardwareRawTransmit = "raw_frame_transmit"
)

// Parameter is one module input, published in the capability contract so an
// orchestrator can ask for a run it knows how to describe.
type Parameter struct {
	// Name is the parameter's key, as passed with --param name=value.
	Name string

	// Kind describes the value: "string", "int", "duration", "bool", "mac".
	Kind string

	// Description is the one-line explanation published in the contract.
	Description string

	// Required marks a parameter the module refuses to run without. The
	// executor enforces it before any I/O, so a missing parameter is a usage
	// error rather than a failure discovered mid-transmission.
	Required bool

	// Default is the value used when the parameter is absent. An empty default
	// with Required set is a module bug and is refused at registration.
	Default string
}

// Meta is everything a module declares about itself. It is the whole of the
// module's public contract: nothing here is discovered at run time, so the
// capability registry can publish it without executing anything.
type Meta struct {
	// ID is the stable dotted identifier, e.g. "wifi.inject.verify". It is the
	// only thing a caller needs to name a module.
	ID string

	// Title is the short human name.
	Title string

	// Description is one sentence on the question the module answers.
	Description string

	// Domain is "wifi" or "bluetooth".
	Domain string

	// Class is the operation class. The executor refuses a module run under a
	// verb that does not match its class, so `mansa exploit` cannot run a
	// validation module and inherit the wrong gates.
	Class models.OperationClass

	// Risk is the published risk rating: low, medium, high, critical.
	Risk string

	// Reversible reports whether the run can be undone. An exploit is not
	// reversible; it records a CleanupState instead.
	Reversible bool

	// SimulationAvailable declares that --sim can run this module. A module
	// that does not declare it is refused a simulated run rather than quietly
	// reporting a fixture result as a real observation.
	SimulationAvailable bool

	// RequiredHardware names the hardware requirements from the constants
	// above. A requirement the provider cannot satisfy makes the run
	// `unavailable`, never a pass and never a silent downgrade to simulation.
	RequiredHardware []string

	// MaxDuration bounds the run. The executor applies it as a context
	// timeout, so a module cannot overrun it by ignoring its own clock.
	MaxDuration time.Duration

	// MaxFrames bounds frames per run. It is enforced three times over: the
	// module refuses a count above it, the transmit harness caps it, and the
	// executor's HardLimit caps it again. A count above the ceiling is refused
	// rather than clamped, because a silent clamp would run a different test
	// than the one that was asked for.
	MaxFrames int

	// Parameters are the module's inputs.
	Parameters []Parameter

	// TargetTypes are the target scopes the module accepts. A module declared
	// for bssid is refused an interface target rather than guessing.
	TargetTypes []models.TargetType

	// The remaining fields are the exploitation declaration. The exploit
	// registry refuses registration without them, so they are always empty on
	// a validation or active-test module.
	//
	// VulnerabilityClass names the weakness being proven.
	VulnerabilityClass string

	// Component names the affected protocol component.
	Component string

	// ExpectedEvidence states what would establish exploitability.
	ExpectedEvidence string

	// Prerequisites states what must be true before a run means anything.
	Prerequisites []string

	// Cleanup states what must be restored or verified afterwards.
	Cleanup string

	// Limitations states what a result does not establish. It is published in
	// the contract and copied into every record, because the most damaging
	// report is the one that implies more than was shown.
	Limitations []string
}

// Module is one registered operation.
type Module interface {
	// Meta returns the module's declaration. It is called at registration and
	// again when the capability contract is built, so it must be cheap and
	// must not depend on run state.
	Meta() Meta

	// Run executes the module. It is called only after every gate has passed,
	// including --dry-run planning, so a module never has to re-check whether
	// it was allowed to run.
	Run(ctx context.Context, ex *Execution) (Outcome, error)
}

// Outcome is what a module reports back to the executor.
//
// Everything here is a statement the module can support with something it
// observed. FramesTransmitted is what the kernel accepted and is never
// described as delivery; a module that saw nothing reports no finding rather
// than a negative result it cannot support, because radio conditions produce
// the same silence as working protection.
type Outcome struct {
	// Notes are neutral statements about what happened.
	Notes []string

	// Limitations are added to the module's declared limitations. They are
	// recorded on the operation and shown by `mansa evidence`.
	Limitations []string

	// References are identifiers a reader can look up: a frame type, a reason
	// code, an RFC section.
	References []string

	// Findings are what the run concluded.
	Findings []models.Finding

	// Evidence is the supporting data, including the per-run digest of the
	// exact bytes transmitted.
	Evidence []models.Evidence

	// FramesTransmitted and BytesTransmitted are what the kernel accepted.
	FramesTransmitted uint64
	BytesTransmitted  uint64

	// CleanupRequired marks a run that left the target's state needing
	// verification. A disruption run sets it: frames left the host and the
	// station is expected to reconnect on its own.
	CleanupRequired bool

	// CleanupState is what actually happened.
	CleanupState models.CleanupState

	// CleanupVerified marks a module that confirmed the post-condition itself.
	// Only a module that watched for it may set it.
	CleanupVerified bool
}

// Execution is the environment handed to a module at run time.
type Execution struct {
	// Request is the resolved, gated request.
	Request Request

	// Backend is the provider the run reads through. In a simulated run it is
	// the deterministic fixture provider.
	Backend transport.Backend

	// Transmit is the raw frame writer. It is nil for a module that declares
	// no transmit requirement, so a validation module cannot emit by accident.
	Transmit Transmitter

	// Events is the structured stream, or nil when events are disabled.
	Events *events.Stream

	// Session supplies collected observations and receives the record. It is
	// nil for a run with no session.
	Session *models.Session

	// Database is a saved GATT attribute table path, for the modules that
	// review one. Empty when none was supplied.
	Database string

	// MaxFrames is the executor's effective frame ceiling for this run: the
	// module's own limit and the executor's HardLimit, whichever is smaller.
	// A module reads it rather than repeating its own constant, so the bound
	// that is enforced is the bound the module was told about.
	MaxFrames int

	// Now returns the current time, injectable so a test need not sleep.
	Now func() time.Time

	// NewID mints record identifiers.
	NewID func(string) string
}

// Transmitter is the raw frame write path, narrowed to what a module needs.
//
// It is separate from transport.Backend because most providers can capture and
// cannot transmit, and a module holding a Backend could reach for a capability
// its provider does not have.
type Transmitter interface {
	// TransmitLinkType reports the kernel link-layer format the interface
	// expects on transmit. Frames carry the matching header.
	TransmitLinkType(iface string) (uint32, error)

	// Transmit writes frames in order. It returns the number of frames the
	// kernel accepted, which is never proof that any of them reached the air.
	Transmit(ctx context.Context, iface string, frames [][]byte) (transport.TransmitStats, error)

	// ProbeTransmit reports whether the interface can accept raw writes.
	ProbeTransmit(iface string) (models.TransmitCapability, error)
}

// Registry holds the registered modules.
//
// It is safe for concurrent reads, which the capability command and the TUI's
// registry view both do while a run may be registering nothing but reading.
type Registry struct {
	byID    map[string]Module
	ordered []string
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{byID: make(map[string]Module)}
}

// Register adds a module, refusing one whose declaration is incomplete.
//
// An incomplete declaration is refused here rather than at run time because the
// capability contract is built from these declarations: a module missing a
// title or a target scope would publish an entry no caller could use.
func (r *Registry) Register(m Module) error {
	if m == nil {
		return fmt.Errorf("refusing to register a nil module")
	}
	meta := m.Meta()
	if meta.ID == "" {
		return fmt.Errorf("refusing to register a module with no id")
	}
	if meta.Title == "" {
		return fmt.Errorf("refusing to register %s: no title", meta.ID)
	}
	if meta.Class == "" {
		return fmt.Errorf("refusing to register %s: no operation class", meta.ID)
	}
	if len(meta.TargetTypes) == 0 {
		return fmt.Errorf("refusing to register %s: declares no target types", meta.ID)
	}
	for _, parameter := range meta.Parameters {
		if parameter.Required && parameter.Default != "" {
			return fmt.Errorf("refusing to register %s: parameter %q is required and also has a default", meta.ID, parameter.Name)
		}
	}
	for _, requirement := range meta.RequiredHardware {
		if requirement != HardwareMonitorMode && requirement != HardwareRawTransmit {
			return fmt.Errorf("refusing to register %s: unknown hardware requirement %q", meta.ID, requirement)
		}
	}
	if _, exists := r.byID[meta.ID]; exists {
		return fmt.Errorf("module %s is already registered", meta.ID)
	}
	r.byID[meta.ID] = m
	r.ordered = append(r.ordered, meta.ID)
	sort.Strings(r.ordered)
	return nil
}

// MustRegister adds modules and panics on a rejected one.
//
// It is for package-level wiring, where a rejected declaration is a build-time
// mistake rather than a runtime condition. Anything that can be influenced by
// input uses Register.
func (r *Registry) MustRegister(modules ...Module) {
	for _, m := range modules {
		if err := r.Register(m); err != nil {
			panic(err)
		}
	}
}

// Get resolves a module by id.
func (r *Registry) Get(id string) (Module, bool) {
	m, ok := r.byID[id]
	return m, ok
}

// Modules returns every registered module in id order.
func (r *Registry) Modules() []Module {
	out := make([]Module, 0, len(r.ordered))
	for _, id := range r.ordered {
		out = append(out, r.byID[id])
	}
	return out
}

// List returns every registered module's declaration in id order.
func (r *Registry) List() []Meta {
	out := make([]Meta, 0, len(r.ordered))
	for _, id := range r.ordered {
		out = append(out, r.byID[id].Meta())
	}
	return out
}

// ByClass returns the modules of one class in id order. It is what the CLI's
// `list` subcommand prints, so the list a user reads is the registry itself
// rather than a second copy of it.
func (r *Registry) ByClass(class models.OperationClass) []Meta {
	var out []Meta
	for _, meta := range r.List() {
		if meta.Class == class {
			out = append(out, meta)
		}
	}
	return out
}

// HasHardware reports whether a module declares a hardware requirement.
func (m Meta) HasHardware(requirement string) bool {
	for _, r := range m.RequiredHardware {
		if r == requirement {
			return true
		}
	}
	return false
}

// AcceptsTarget reports whether the module declares this target scope.
func (m Meta) AcceptsTarget(targetType models.TargetType) bool {
	for _, t := range m.TargetTypes {
		if t == targetType {
			return true
		}
	}
	return false
}

// Parameter looks up a declared parameter by name.
func (m Meta) Parameter(name string) (Parameter, bool) {
	for _, p := range m.Parameters {
		if p.Name == name {
			return p, true
		}
	}
	return Parameter{}, false
}

// Summary renders a one-line description for a list view.
func (m Meta) Summary() string {
	var b strings.Builder
	b.WriteString(m.Title)
	if m.Risk != "" {
		b.WriteString("  [")
		b.WriteString(m.Risk)
		b.WriteString("]")
	}
	return b.String()
}
