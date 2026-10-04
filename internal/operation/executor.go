package operation

import (
	"context"
	"fmt"
	"time"

	"github.com/QYVORA/qyvora-mansa/internal/events"
	"github.com/QYVORA/qyvora-mansa/internal/transport"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// DefaultHardLimit is the executor's own frame ceiling.
//
// It is deliberately independent of every module. A module that declares a
// larger ceiling is describing what it would like to do; this is what the
// process will allow, so a mistake in one module's declaration cannot raise the
// process-wide bound.
const DefaultHardLimit = 256

// Executor runs modules through the gates every class shares.
type Executor struct {
	// Registry resolves the module.
	Registry *Registry

	// Backend is the provider modules read and probe through.
	Backend transport.Backend

	// Events is the structured stream, or nil when events are disabled.
	Events *events.Stream

	// HardLimit caps frames per run independently of the module. Zero means
	// DefaultHardLimit.
	HardLimit int

	// MaxDuration caps a run that declares none. Zero means DefaultMaxDuration.
	MaxDuration time.Duration

	// Confirm asks the operator to approve a run whose class affects the
	// target's environment. The CLI supplies it; a test does not.
	Confirm func(module Meta, req Request) error

	// Now supplies the clock used for record timestamps and module execution.
	// It is injectable so a test need not sleep, and so a run's timestamps are
	// reproducible. Nil means the wall clock.
	Now func() time.Time
}

// DefaultMaxDuration bounds a run that declares no limit of its own, so a
// module cannot leave the executor without one.
const DefaultMaxDuration = 60 * time.Second

// RefusalError is a gate refusal. It carries the record so a refused run is
// still recorded and still reports why, rather than leaving nothing behind.
type RefusalError struct {
	// Status is StatusRefused or StatusUnavailable.
	Status models.OperationStatus

	// Gate names the gate that refused, e.g. "authorization".
	Gate string

	// Reason is the human explanation.
	Reason string

	// Err is the underlying cause, when there is one.
	Err error
}

func (e *RefusalError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s gate: %s: %v", e.Gate, e.Reason, e.Err)
	}
	return fmt.Sprintf("%s gate: %s", e.Gate, e.Reason)
}

func (e *RefusalError) Unwrap() error { return e.Err }

// Execute runs one module and returns the record of what happened.
//
// Every run produces a record, including a refused one: a refusal that leaves
// no trace is indistinguishable from a run that was never attempted, and the
// difference matters when reviewing what was asked of the radio.
//
// A refused or unavailable run returns both the record and a *RefusalError, so
// a caller can render the record and still exit non-zero.
func (e *Executor) Execute(ctx context.Context, req Request) (models.OperationRecord, error) {
	module, ok := e.Registry.Get(req.ModuleID)
	if !ok {
		// The module cannot be resolved, so there is no declaration to build a
		// record from. This is the one failure with no record: nothing is known
		// about what was asked beyond the id.
		return models.OperationRecord{}, fmt.Errorf("no operation module %q is registered", req.ModuleID)
	}
	meta := module.Meta()

	record := newRecord(e, meta, req)
	if start, ok := startEvent(meta.Class); ok {
		e.emit(start, map[string]any{
			"operation": meta.ID, "class": meta.Class.String(),
			"target": targetLabel(req), "interface": req.Interface,
			"simulated": req.Simulated, "dry_run": req.DryRun,
			"execution_id": record.ExecutionID,
		})
	}

	// finish emits exactly one terminal event and returns the run's error. It is
	// deferred so a panic or an early return cannot leave a started event with
	// no terminal event, which would strand a consumer tailing the stream.
	finished := false
	finish := func(status models.OperationStatus, data map[string]any) {
		if finished {
			return
		}
		finished = true
		if data == nil {
			data = map[string]any{}
		}
		data["operation"] = meta.ID
		data["class"] = meta.Class.String()
		data["status"] = status
		data["execution_id"] = record.ExecutionID
		switch status {
		case models.StatusRefused, models.StatusUnavailable:
			e.emit(events.OperationRefused, data)
		case models.StatusCancelled:
			e.emit(events.OperationCancelled, data)
		default:
			if terminal, ok := terminalEvent(meta.Class); ok {
				e.emit(terminal, data)
			}
		}
	}

	if err := e.gate(meta, req); err != nil {
		var refusal *RefusalError
		status := models.StatusRefused
		reason := err.Error()
		if asRefusal(err, &refusal) {
			status = refusal.Status
			reason = refusal.Reason
		}
		record.Status = status
		record.Error = reason
		record.CleanupState = models.CleanupNotRequired
		record.FinishedAt = e.now()
		record.Duration = record.FinishedAt.Sub(record.StartedAt).String()
		finish(status, map[string]any{"gate": gateName(err), "reason": reason, "target": targetLabel(req)})
		return record, err
	}

	// The hardware gate needs to probe, which is I/O, so it runs after the
	// gates that need none. A --sim run probes the fixture provider, which
	// reports simulated rather than pretending to have hardware.
	transmit, err := e.resolveTransmitter(meta, req)
	if err != nil {
		record.Status = models.StatusUnavailable
		record.Error = err.Error()
		record.CleanupState = models.CleanupNotRequired
		record.FinishedAt = e.now()
		record.Duration = record.FinishedAt.Sub(record.StartedAt).String()
		finish(models.StatusUnavailable, map[string]any{"gate": "hardware", "reason": err.Error()})
		return record, err
	}

	if req.DryRun {
		record.Status = models.StatusPlanned
		record.Notes = append(record.Notes, planNotes(meta, req)...)
		record.CleanupState = models.CleanupNotRequired
		record.FinishedAt = e.now()
		record.Duration = record.FinishedAt.Sub(record.StartedAt).String()
		finish(models.StatusPlanned, map[string]any{"frames": record.FramesTransmitted})
		return record, nil
	}

	hardLimit := e.hardLimit()
	effective := meta.MaxFrames
	if effective <= 0 || effective > hardLimit {
		effective = hardLimit
	}

	execution := &Execution{
		Request:   req,
		Backend:   e.Backend,
		Transmit:  transmit,
		Events:    e.Events,
		Session:   req.Session,
		Database:  req.Database,
		MaxFrames: effective,
		Now:       e.now,
		NewID:     models.NewID,
	}

	runCtx := ctx
	if deadline := e.durationLimit(meta); deadline > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, deadline)
		defer cancel()
	}

	outcome, runErr := module.Run(runCtx, execution)

	record.FramesTransmitted = outcome.FramesTransmitted
	record.BytesTransmitted = outcome.BytesTransmitted
	record.Notes = append(record.Notes, outcome.Notes...)
	record.Limitations = mergeLimitations(meta.Limitations, outcome.Limitations)
	record.References = outcome.References
	record.Findings = outcome.Findings
	record.Evidence = outcome.Evidence
	record.CleanupRequired = outcome.CleanupRequired

	switch {
	case runErr != nil && ctx.Err() != nil && !req.Simulated:
		// The caller's context ended the run. Recorded as cancelled rather than
		// failed: nothing went wrong, the operator stopped it.
		record.Status = models.StatusCancelled
		record.Error = "cancelled"
		record.CleanupState = cleanupState(outcome)
		finish(models.StatusCancelled, map[string]any{"reason": "cancelled by the operator"})
		return record, runErr
	case runErr != nil:
		record.Status = models.StatusFailed
		record.Error = runErr.Error()
		record.CleanupState = cleanupState(outcome)
		finish(models.StatusFailed, map[string]any{"reason": runErr.Error()})
		return record, runErr
	}

	record.Status = models.StatusCompleted
	record.CleanupState = cleanupState(outcome)
	record.FinishedAt = e.now()
	record.Duration = record.FinishedAt.Sub(record.StartedAt).String()

	if record.FramesTransmitted > 0 {
		e.emit(events.FramesTransmitted, map[string]any{
			"operation": meta.ID, "interface": req.Interface,
			"frames": record.FramesTransmitted, "bytes": record.BytesTransmitted,
			"simulated": req.Simulated,
		})
	}

	finish(models.StatusCompleted, map[string]any{
		"frames":        record.FramesTransmitted,
		"bytes":         record.BytesTransmitted,
		"findings":      len(outcome.Findings),
		"cleanup_state": record.CleanupState,
	})
	return record, nil
}

// gate applies every gate that needs no I/O, in the documented order.
//
// The order is the contract. Module resolution comes first because nothing else
// can be evaluated without a declaration; parameters next because a missing
// one is a usage mistake and should be reported as one, before the operator is
// asked to authorize a run that was never going to start.
func (e *Executor) gate(meta Meta, req Request) error {
	module, ok := e.Registry.Get(req.ModuleID)
	if !ok {
		return &RefusalError{Status: models.StatusRefused, Gate: "resolution", Reason: fmt.Sprintf("no module %q is registered", req.ModuleID)}
	}
	if module.Meta().Class != req.Class {
		return &RefusalError{
			Status: models.StatusRefused, Gate: "resolution",
			Reason: fmt.Sprintf("%s is a %s module and cannot run under %s", meta.ID, module.Meta().Class, req.Class),
		}
	}

	if unknown := req.unknownParams(meta); len(unknown) > 0 {
		return &RefusalError{
			Status: models.StatusRefused, Gate: "parameters",
			Reason: fmt.Sprintf("%s does not declare %s", meta.ID, joinList(unknown)),
			Err:    fmt.Errorf("check the spelling of --param"),
		}
	}
	if missing := req.missingParams(meta); len(missing) > 0 {
		return &RefusalError{
			Status: models.StatusRefused, Gate: "parameters",
			Reason: fmt.Sprintf("%s requires %s", meta.ID, joinList(missing)),
		}
	}

	if req.Target == nil || req.Target.Value == "" {
		return &RefusalError{
			Status: models.StatusRefused, Gate: "target",
			Reason: "an operation run must name a target",
		}
	}

	// A simulated run is never recorded against a real target's authorization,
	// so it is not gated on one: there is nothing over the air to be authorized
	// against. The record says simulated, which is the honest description.
	if !req.Simulated && !req.Target.Authorized() {
		return &RefusalError{
			Status: models.StatusRefused, Gate: "authorization",
			Reason: fmt.Sprintf("target %s is not authorized; re-run with --authorized to confirm scope", req.Target.DisplayName()),
		}
	}

	if !meta.AcceptsTarget(req.Target.Type) {
		accepted := make([]string, 0, len(meta.TargetTypes))
		for _, t := range meta.TargetTypes {
			accepted = append(accepted, string(t))
		}
		return &RefusalError{
			Status: models.StatusRefused, Gate: "scope",
			Reason: fmt.Sprintf("%s accepts %s, not a %s target", meta.ID, joinList(accepted), req.Target.Type),
		}
	}

	if req.Simulated && !meta.SimulationAvailable {
		return &RefusalError{
			Status: models.StatusRefused, Gate: "simulation",
			Reason: fmt.Sprintf("%s does not declare a simulation path; a fixture result would not be an observation of anything", meta.ID),
		}
	}

	// The confirmation gate is last, so the operator is never asked to approve a
	// run that a cheaper gate was going to refuse.
	if meta.Class.RequiresConfirmation() && !req.DryRun && e.Confirm != nil {
		if err := e.Confirm(meta, req); err != nil {
			return &RefusalError{Status: models.StatusRefused, Gate: "confirmation", Reason: err.Error(), Err: err}
		}
	}
	return nil
}

// resolveTransmitter supplies the transmit path, or explains why there is none.
//
// A module that declares raw_frame_transmit is refused unless the provider can
// probe the named interface and reports it writable. The refusal is
// `unavailable`, never a pass, and never a quiet downgrade to a simulated run:
// silently changing what was tested is worse than refusing.
func (e *Executor) resolveTransmitter(meta Meta, req Request) (Transmitter, error) {
	if !meta.HasHardware(HardwareRawTransmit) {
		return nil, nil
	}
	if e.Backend == nil {
		return nil, &RefusalError{Status: models.StatusUnavailable, Gate: "hardware", Reason: "no wireless provider is available"}
	}
	probe, ok := e.Backend.(interface {
		ProbeTransmit(string) (models.TransmitCapability, error)
	})
	if !ok {
		return nil, &RefusalError{
			Status: models.StatusUnavailable, Gate: "hardware",
			Reason: fmt.Sprintf("provider %s cannot report raw transmit capability", e.Backend.Name()),
		}
	}
	iface := req.Interface
	if iface == "" {
		iface = req.Target.Interface
	}
	if iface == "" {
		return nil, &RefusalError{
			Status: models.StatusUnavailable, Gate: "hardware",
			Reason: fmt.Sprintf("%s needs an interface to transmit on", meta.ID),
		}
	}
	capability, err := probe.ProbeTransmit(iface)
	if err != nil {
		return nil, &RefusalError{Status: models.StatusUnavailable, Gate: "hardware",
			Reason: fmt.Sprintf("cannot determine whether %s accepts raw frames", iface), Err: err}
	}
	if !capability.Writable {
		reason := capability.WritableReason
		if reason == "" {
			reason = "the interface did not report itself writable"
		}
		return nil, &RefusalError{Status: models.StatusUnavailable, Gate: "hardware",
			Reason: fmt.Sprintf("%s cannot accept raw frame writes: %s", iface, reason)}
	}
	tx, ok := e.Backend.(Transmitter)
	if !ok {
		return nil, &RefusalError{
			Status: models.StatusUnavailable, Gate: "hardware",
			Reason: fmt.Sprintf("provider %s cannot transmit raw frames", e.Backend.Name()),
		}
	}
	return tx, nil
}

// cleanupState resolves what the record says about cleanup.
//
// A module that required cleanup and confirmed it reports completed. One that
// required it and did not confirm reports pending rather than completed,
// because frames left the host and nobody watched for the post-condition.
func cleanupState(outcome Outcome) models.CleanupState {
	switch {
	case !outcome.CleanupRequired:
		return models.CleanupNotRequired
	case outcome.CleanupVerified:
		return models.CleanupCompleted
	default:
		return models.CleanupPending
	}
}

// planNotes describes what a dry run would do.
//
// The plan is produced after the gates, so it cannot describe a run that would
// be refused. It reports what was decided, never what was observed: nothing was
// transmitted and nothing was collected.
func planNotes(meta Meta, req Request) []string {
	notes := []string{
		fmt.Sprintf("dry run: %s was not transmitted and nothing was collected", meta.ID),
	}
	if len(meta.Parameters) > 0 {
		names := make([]string, 0, len(meta.Parameters))
		for _, parameter := range meta.Parameters {
			value := req.Param(meta, parameter.Name)
			switch {
			case value == "" && parameter.Default != "":
				value = parameter.Default + " (default)"
			case value == "":
				value = "<unset>"
			}
			names = append(names, parameter.Name+"="+value)
		}
		notes = append(notes, "parameters: "+joinList(names))
	}
	if meta.MaxFrames > 0 {
		notes = append(notes, fmt.Sprintf("frame ceiling: %d", meta.MaxFrames))
	}
	if len(meta.RequiredHardware) > 0 {
		notes = append(notes, "requires: "+joinList(meta.RequiredHardware))
	}
	if len(meta.Limitations) > 0 {
		notes = append(notes, "limitations: "+joinList(meta.Limitations))
	}
	// A plan runs no harness, so nothing else will say what an accepted write and
	// an empty listen window would mean. Stating it here keeps the plan as
	// cautious as the run it is planning.
	if meta.HasHardware(HardwareRawTransmit) {
		notes = append(notes,
			"planned frames transmitted would be what the kernel accepted, not proof that any frame reached the air",
			"an empty listen window would not be a negative result: radio conditions and working protection produce the same silence")
	}
	if req.Simulated {
		notes = append(notes, "simulation: no frame reaches the air on this path")
	}
	return notes
}

func (e *Executor) hardLimit() int {
	if e.HardLimit > 0 {
		return e.HardLimit
	}
	return DefaultHardLimit
}

func (e *Executor) durationLimit(meta Meta) time.Duration {
	if meta.MaxDuration > 0 {
		return meta.MaxDuration
	}
	if e.MaxDuration > 0 {
		return e.MaxDuration
	}
	return DefaultMaxDuration
}

func (e *Executor) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now().UTC()
}

func (e *Executor) emit(name string, data map[string]any) {
	if e.Events != nil {
		e.Events.Info(name, data)
	}
}

// newRecord builds the record skeleton, so every run is recorded with the same
// fields whether it completed, was refused, or failed.
func newRecord(e *Executor, meta Meta, req Request) models.OperationRecord {
	record := models.OperationRecord{
		ID:        models.NewID("op"),
		ModuleID:  meta.ID,
		Title:     meta.Title,
		Class:     meta.Class,
		Domain:    meta.Domain,
		Risk:      meta.Risk,
		Target:    targetLabel(req),
		Interface: req.Interface,
		Operator:  req.Operator,
		Simulated: req.Simulated,
		StartedAt: e.now(),
	}
	if req.Target != nil {
		record.TargetType = req.Target.Type
		record.Scope = req.Target.Authorization.Scope
		record.Authorized = req.Target.Authorization.Granted
		record.AuthorizationMethod = req.Target.Authorization.Method
	}
	if req.Session != nil {
		record.SessionID = req.Session.ID
	}
	if e.Events != nil {
		record.ExecutionID = e.Events.ExecutionID()
	}
	if req.Simulated {
		// A simulated run's authorization method states that it simulated,
		// so the record never implies a human authorized radio traffic that
		// was never sent.
		record.AuthorizationMethod = "simulation"
	}
	return record
}

func targetLabel(req Request) string {
	if req.Target == nil {
		return ""
	}
	return req.Target.Value
}

// startEvent and terminalEvent map a class to its lifecycle events.
//
// Every class gets a pair so a consumer can follow a run without knowing which
// verb started it. A class with no pair still gets the generic refusal and
// cancellation events.
func startEvent(class models.OperationClass) (string, bool) {
	switch class {
	case models.ClassValidation:
		return events.ValidationStarted, true
	case models.ClassActiveTest:
		return events.ActiveTestStarted, true
	case models.ClassExploitation:
		return events.ExploitStarted, true
	default:
		return "", false
	}
}

func terminalEvent(class models.OperationClass) (string, bool) {
	switch class {
	case models.ClassValidation:
		return events.ValidationCompleted, true
	case models.ClassActiveTest:
		return events.ActiveTestCompleted, true
	case models.ClassExploitation:
		return events.ExploitCompleted, true
	default:
		return "", false
	}
}

func gateName(err error) string {
	var refusal *RefusalError
	if asRefusal(err, &refusal) {
		return refusal.Gate
	}
	return "unknown"
}

func asRefusal(err error, out **RefusalError) bool {
	for err != nil {
		if refusal, ok := err.(*RefusalError); ok {
			*out = refusal
			return true
		}
		unwrapper, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = unwrapper.Unwrap()
	}
	return false
}

func joinList(values []string) string {
	switch len(values) {
	case 0:
		return ""
	case 1:
		return values[0]
	default:
		out := ""
		for i, value := range values {
			if i > 0 {
				out += ", "
			}
			out += value
		}
		return out
	}
}

// mergeLimitations concatenates two limitation lists without repeats, keeping
// the module's declaration first and the run's own additions after it.
//
// A module naturally seeds its outcome with its own declaration, so a plain
// append would print every declaration twice and make a report look padded. The
// result is also a fresh slice: appending to meta.Limitations in place could
// write into a module's own backing array, which is shared with every later call
// to Meta.
func mergeLimitations(declared, observed []string) []string {
	merged := make([]string, 0, len(declared)+len(observed))
	seen := make(map[string]bool, len(declared)+len(observed))
	for _, group := range [][]string{declared, observed} {
		for _, limitation := range group {
			if seen[limitation] {
				continue
			}
			seen[limitation] = true
			merged = append(merged, limitation)
		}
	}
	return merged
}
