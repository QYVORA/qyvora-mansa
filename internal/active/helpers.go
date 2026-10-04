package active

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/QYVORA/qyvora-mansa/internal/lab"
	"github.com/QYVORA/qyvora-mansa/internal/operation"
	"github.com/QYVORA/qyvora-mansa/internal/transport"
	"github.com/QYVORA/qyvora-mansa/internal/wireless"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// requiredMAC reads a required MAC parameter and refuses a value that is not a
// MAC address.
//
// It also refuses the broadcast address, because every transmitting module here
// is scoped to one authorized peer: a parameter that silently accepted
// ff:ff:ff:ff:ff:ff would let a broadcast frame through the one gate that is
// supposed to prevent it.
func requiredMAC(ex *operation.Execution, meta operation.Meta, name string) (wireless.MACAddress, error) {
	raw := ex.Request.Param(meta, name)
	if raw == "" {
		return wireless.MACAddress{}, fmt.Errorf("parameter %q is required", name)
	}
	address, err := wireless.ParseMACAddress(raw)
	if err != nil {
		return wireless.MACAddress{}, fmt.Errorf("parameter %q must be a MAC address: %w", name, err)
	}
	if address.IsBroadcast() {
		return wireless.MACAddress{}, fmt.Errorf("parameter %q must be one station, not the broadcast address", name)
	}
	if address.IsZero() {
		return wireless.MACAddress{}, fmt.Errorf("parameter %q must not be the all-zero address", name)
	}
	return address, nil
}

// targetMAC returns the authorized target's MAC address.
func targetMAC(ex *operation.Execution) (string, error) {
	if ex.Request.Target == nil {
		return "", fmt.Errorf("a target is required")
	}
	value := ex.Request.Target.Value
	if value == "" {
		value = ex.Request.Target.DisplayName()
	}
	address, err := wireless.ParseMACAddress(value)
	if err != nil {
		return "", fmt.Errorf("target %q must be a BSSID for this module: %w", value, err)
	}
	if address.IsBroadcast() {
		return "", fmt.Errorf("target must not be the broadcast address")
	}
	return address.String(), nil
}

// planProbeRequests validates the count and observe parameters and builds the
// frame set, one probe request per frame.
//
// The count is refused above the ceiling rather than clamped: a clamped run
// would report a smaller test than the operator asked for, which is exactly the
// confusion the bounds exist to prevent.
func planProbeRequests(ex *operation.Execution, meta operation.Meta, source wireless.MACAddress) (int, time.Duration, [][]byte, error) {
	count, err := ex.Request.IntParam(meta, "count")
	if err != nil {
		return 0, 0, nil, err
	}
	if count < 1 {
		return 0, 0, nil, fmt.Errorf("parameter %q must be at least 1, got %d", "count", count)
	}
	ceiling := min(meta.MaxFrames, ex.MaxFrames)
	if ceiling > 0 && count > ceiling {
		return 0, 0, nil, fmt.Errorf("parameter %q is %d, above the %d frame ceiling for this run", "count", count, ceiling)
	}
	observe, err := ex.Request.DurationParam(meta, "observe", lab.MaxListenWindow)
	if err != nil {
		return 0, 0, nil, err
	}
	frames, err := buildProbeRequests(source, ex.Request.Param(meta, "ssid"), count)
	if err != nil {
		return 0, 0, nil, err
	}
	return count, observe, frames, nil
}

// defaultProbeSSID is the SSID a probe request names when the operator supplied
// none. It is reported in the run notes so the record says which SSID was asked
// for rather than leaving the reader to guess.
const defaultProbeSSID = "mansa-probe"

// ssidOf reports the SSID a run probes for.
func ssidOf(ex *operation.Execution) string {
	if ex.Request.Params["ssid"] != "" {
		return ex.Request.Params["ssid"]
	}
	return defaultProbeSSID
}

// buildProbeRequests builds count probe requests, each carrying a radiotap
// header because the transmit link type requires one.
func buildProbeRequests(source wireless.MACAddress, ssid string, count int) ([][]byte, error) {
	if ssid == "" {
		ssid = defaultProbeSSID
	}
	frames := make([][]byte, 0, count)
	sequence := uint16(1)
	for index := 0; index < count; index++ {
		body, err := wireless.BuildProbeRequest(source, []byte(ssid), sequence)
		if err != nil {
			return nil, fmt.Errorf("build probe request %d: %w", index, err)
		}
		frames = append(frames, append(wireless.RadiotapHeader(), body...))
		sequence = wireless.SequenceNumber(sequence)
	}
	return frames, nil
}

// listenerOf returns the passive read path, or nil when the provider has none.
// A run with no listener transmits and reports no observation rather than
// pretending the transmit result was an observation.
func listenerOf(ex *operation.Execution) lab.Listener {
	if ex.Backend == nil {
		return nil
	}
	listener, ok := ex.Backend.(lab.Listener)
	if !ok {
		return nil
	}
	return listener
}

// describeFrame renders a one-line description of an observed frame.
func describeFrame(packet []byte) (string, error) {
	info, err := wireless.ParseFrame(packet)
	if err != nil {
		return "", err
	}
	if info.Type != wireless.FrameManagement {
		return fmt.Sprintf("%s frame, %d byte(s)", info.Type, len(packet)), nil
	}
	return fmt.Sprintf("%s subtype %d from %s to %s, %d byte(s)",
		info.Type, info.Subtype,
		wireless.MACAddress(info.Address2), wireless.MACAddress(info.Address1), len(packet)), nil
}

// countFramesFor counts observed frames of one management subtype.
func countFramesFor(result lab.Result, subtype uint8) int {
	count := 0
	for _, frame := range result.Frames {
		info, err := wireless.ParseFrame(frame.Bytes)
		if err != nil {
			continue
		}
		if info.Type == wireless.FrameManagement && info.Subtype == subtype {
			count++
		}
	}
	return count
}

// frameFor reports whether an observed frame names the given address as its
// receiver.
func frameFor(packet []byte, address string) bool {
	info, err := wireless.ParseFrame(packet)
	if err != nil {
		return false
	}
	if !info.HasAddress1 {
		return false
	}
	return equalMAC(wireless.MACAddress(info.Address1).String(), address)
}

// authenticationStatuses extracts the status codes from observed authentication
// frames, in order and without duplicates, so a run that saw the same answer
// three times reports one answer rather than implying three.
func authenticationStatuses(frames []lab.Frame) []uint16 {
	seen := map[uint16]bool{}
	var out []uint16
	for _, frame := range frames {
		info, err := wireless.ParseFrame(frame.Bytes)
		if err != nil || info.Type != wireless.FrameManagement || info.Subtype != wireless.SubtypeAuthentication {
			continue
		}
		status, ok := authenticationStatus(frame.Bytes)
		if !ok || seen[status] {
			continue
		}
		seen[status] = true
		out = append(out, status)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// authenticationStatus reads the status code from an authentication frame body,
// which follows the 24 byte MAC header.
func authenticationStatus(packet []byte) (uint16, bool) {
	const authenticationHeader = 24
	if len(packet) < authenticationHeader+4 {
		return 0, false
	}
	return uint16(packet[authenticationHeader+2]) | uint16(packet[authenticationHeader+3])<<8, true
}

// equalMAC compares two MAC address strings without regard to case or separator.
func equalMAC(a, b string) bool {
	return normalizeMAC(a) == normalizeMAC(b)
}

// observationFinding builds a finding that reports only what the run observed.
//
// Confidence is bounded by the quality of the evidence: a run reports ConfObserved
// when the kernel accepted the frames, because an accepted write is not proof of
// a frame on the air.
func observationFinding(ruleID, title, category string, severity models.Severity, confidence models.Confidence, description, target, limitation string, evidence []models.Evidence) models.Finding {
	references := []string{"IEEE Std 802.11-2020"}
	return models.Finding{
		ID:          models.NewID("finding"),
		RuleID:      ruleID,
		Title:       title,
		Category:    category,
		Severity:    severity,
		Confidence:  confidence,
		Description: description,
		Target:      target,
		Status:      models.FindingDetected,
		// The recommendation states what to check next rather than asserting a
		// control is missing, because an observation is not a diagnosis.
		Recommendation: "Confirm the finding in an isolated laboratory before drawing a conclusion about the target's configuration.",
		Evidence:       evidence,
		References:     references,
		Timestamp:      time.Now().UTC(),
	}
}

// normalizeMAC renders a MAC address in a comparable form.
func normalizeMAC(value string) string {
	out := make([]rune, 0, len(value))
	for _, r := range value {
		switch {
		case r == ':' || r == '-' || r == '.' || r == ' ':
			continue
		case r >= 'A' && r <= 'F':
			out = append(out, r+('a'-'A'))
		default:
			out = append(out, r)
		}
	}
	return string(out)
}

// min returns the smaller of two frame ceilings.
func min(a, b int) int {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

// interfaceName is the interface the run transmits and listens on.
func interfaceName(ex *operation.Execution) string { return ex.Request.Interface }

// contextWithDeadline bounds a module's own work below the executor's deadline,
// so a module cannot outlive the run the executor timed out.
func contextWithDeadline(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

// captureStatsRef documents why a module reads through the listener rather than
// asking the provider for statistics: the harness already counted them.
var _ = transport.CaptureStats{}
