package active

import (
	"context"
	"fmt"
	"time"

	"github.com/QYVORA/qyvora-mansa/internal/lab"
	"github.com/QYVORA/qyvora-mansa/internal/operation"
	"github.com/QYVORA/qyvora-mansa/internal/wireless"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// WiFiModules returns the WiFi active-test modules.
//
// Each transmits a small, declared frame set at one authorized target and then
// listens for what the target answered. All three go through the same harness,
// so the bounds and the honesty rules cannot differ between them.
func WiFiModules() []operation.Module {
	return []operation.Module{
		&injectVerify{},
		&managementProtectionProbe{},
		&authenticationProbe{},
	}
}

// transmitCommon is the declaration every transmitting WiFi module shares.
//
// The transmitter address is a declared parameter rather than a value read from
// the adapter, because the frame bytes are recorded: a frame built from whatever
// address the host happened to have would make the recorded bytes unreproducible.
func transmitCommon(id, title, description, source string, required []operation.Parameter, optional []operation.Parameter, maxFrames int, maxDuration time.Duration, prerequisites []string, noiseLevel models.NoiseLevel) operation.Meta {
	parameters := []operation.Parameter{
		{Name: "source", Kind: "mac", Required: true, Description: "transmitter MAC address placed in the constructed frames"},
	}
	parameters = append(parameters, required...)
	parameters = append(parameters, optional...)
	return operation.Meta{
		ID:    id,
		Title: title,
		// The description is what the capability contract publishes as the
		// question the module answers, so dropping it here would leave three
		// modules in the contract with no explanation of what they check.
		Description: description,
		Domain:      "wifi",
		Class:       models.ClassActiveTest,
		NoiseLevel:  noiseLevel,
		Risk:        "medium",
		// An active test emits radio traffic at a target, so it is not reversible
		// in the sense of being undone; it is bounded and scoped.
		Reversible: false,
		// The fixture accepts frames and emits the recorded responses, so a
		// simulated run exercises construction, bounding, and reporting.
		SimulationAvailable: true,
		RequiredHardware:    []string{operation.HardwareRawTransmit, operation.HardwareMonitorMode},
		MaxDuration:         maxDuration,
		MaxFrames:           maxFrames,
		Parameters:          parameters,
		TargetTypes:         []models.TargetType{models.TargetBSSID},
		Prerequisites:       prerequisites,
		// What an accepted write and an empty listen window mean is stated by the
		// transmit harness, which is what observes them. Repeating those facts
		// here would print each one twice without adding anything, so this list
		// holds only what is specific to the module. The dry-run plan carries the
		// harness facts itself, because no harness runs to state them there.
		Limitations: []string{
			"The observation covers one transmit and one listen window; it says nothing about behaviour over a longer assessment.",
		},
	}
}

// injectVerify answers whether this interface transmits and whether anything
// answers at all.
//
// It is the smallest active test available, and it exists because every other
// transmitting module depends on the interface working. A run that observes
// nothing here means the later observations cannot be interpreted.
type injectVerify struct{}

func (m *injectVerify) Meta() operation.Meta {
	return transmitCommon(
		ModuleWiFiInjectVerify,
		"Verify Interface Transmission",
		"Transmit a bounded set of declared frames at the authorized target and report whether anything answered.",
		"wifi-active-test",
		[]operation.Parameter{
			{Name: "count", Kind: "int", Description: "probe requests to send", Default: "5"},
			{Name: "observe", Kind: "duration", Description: "listen window after transmitting", Default: "3s"},
		},
		nil,
		10,
		60*time.Second,
		[]string{
			"The target is an authorized test network or an isolated laboratory.",
			"The interface is in monitor mode and can accept raw frame writes.",
		},
		// Low noise: sends a small number of standards-compliant probe requests.
		models.NoiseLevelLow,
	)
}

func (m *injectVerify) Run(ctx context.Context, ex *operation.Execution) (operation.Outcome, error) {
	meta := m.Meta()
	source, err := requiredMAC(ex, meta, "source")
	if err != nil {
		return operation.Outcome{}, err
	}
	target, err := targetMAC(ex)
	if err != nil {
		return operation.Outcome{}, err
	}
	count, observe, frames, err := planProbeRequests(ex, meta, source)
	if err != nil {
		return operation.Outcome{}, err
	}

	result, err := lab.TransmitAndListen(ctx, ex.Transmit, listenerOf(ex), lab.Options{
		Interface: ex.Request.Interface,
		Frames:    frames,
		FrameCap:  min(meta.MaxFrames, ex.MaxFrames),
		ListenFor: observe,
		Summarize: describeFrame,
		Now:       ex.Now,
	})
	outcome := operation.Outcome{
		Notes:             []string{fmt.Sprintf("Transmitted %d probe request(s) for SSID %q and listened for %s.", count, ssidOf(ex), observe)},
		Limitations:       append(meta.Limitations, "A probe request is unicast-directed in its fields but broadcast in transmission; it does not associate and carries no credentials."),
		FramesTransmitted: result.FramesTransmitted,
		BytesTransmitted:  result.BytesTransmitted,
		CleanupRequired:   false,
		CleanupState:      models.CleanupNotRequired,
	}
	outcome.Evidence = append(outcome.Evidence, result.Evidence("wifi-inject-verify", target))
	outcome.Limitations = append(outcome.Limitations, result.Limitations()...)

	if err != nil {
		return outcome, err
	}
	if result.ObserveError() != nil {
		return outcome, result.ObserveError()
	}

	answered := countFramesFor(result, wireless.SubtypeProbeResponse)
	outcome.Notes = append(outcome.Notes, fmt.Sprintf("Observed %d frame(s) naming the probed SSID in a %s window.", answered, result.ListenedFor))
	if answered == 0 {
		outcome.Limitations = append(outcome.Limitations,
			"No probe response naming the SSID was observed. This does not establish that the interface failed to transmit: an accepted write is not proof of a frame on the air, and a target that did not hear the probe looks identical.")
		return outcome, nil
	}

	outcome.Findings = []models.Finding{observationFinding(
		"WLAN-ACT-001",
		"Authorized target answered probe requests",
		"informational",
		models.SeverityInfo,
		models.ConfObserved,
		fmt.Sprintf("The authorized target returned %d probe response(s) naming the probed SSID within %s of the transmitted requests.", answered, result.ListenedFor),
		target,
		"Observed responses confirm the path between this host and the target. They establish nothing about authentication, encryption, or access control.",
		outcome.Evidence,
	)}
	return outcome, nil
}

// managementProtectionProbe reports whether the target emits any frame addressed
// to a named station during a bounded window.
//
// What it sends is a set of broadcast probe requests, not frames addressed to the
// station. A management frame crafted for a station that has already associated
// would either be rejected as a protocol violation or, if it were a
// deauthentication, would knock that station off the network: neither is
// appropriate for an active_test module, and both belong behind the
// exploitation gates instead.
//
// So this module states the narrower thing it can actually establish. It reports
// frames the target addressed to the station, and it explicitly does not report a
// management frame protection result, because nothing here can distinguish a
// protected frame from an unprotected one that simply went unasked.
type managementProtectionProbe struct{}

func (m *managementProtectionProbe) Meta() operation.Meta {
	return transmitCommon(
		ModuleWiFiManagementProtection,
		"Probe Management Frame Protection",
		"Broadcast a bounded set of declared probe requests and report whether the target emits any frame addressed to one authorized station. This does not establish whether management frame protection is enabled.",
		"wifi-management-probe",
		[]operation.Parameter{
			{Name: "station", Kind: "mac", Required: true, Description: "the one authorized station the frames are addressed to"},
			{Name: "count", Kind: "int", Description: "probe requests to send", Default: "5"},
			{Name: "observe", Kind: "duration", Description: "listen window after transmitting", Default: "3s"},
		},
		nil,
		10,
		60*time.Second,
		[]string{
			"The station is one the operator is authorized to test.",
			"The access point is the authorized target.",
		},
		// Low noise: sends standards-compliant probe requests. While targeted at
		// one station, these blend with normal client scanning behavior.
		models.NoiseLevelLow,
	)
}

func (m *managementProtectionProbe) Run(ctx context.Context, ex *operation.Execution) (operation.Outcome, error) {
	meta := m.Meta()
	source, err := requiredMAC(ex, meta, "source")
	if err != nil {
		return operation.Outcome{}, err
	}
	stationAddress, err := requiredMAC(ex, meta, "station")
	if err != nil {
		return operation.Outcome{}, err
	}
	station := stationAddress.String()
	if _, err := targetMAC(ex); err != nil {
		return operation.Outcome{}, err
	}
	count, observe, frames, err := planProbeRequests(ex, meta, source)
	if err != nil {
		return operation.Outcome{}, err
	}

	// The station is named so the run is scoped and the observation has
	// something specific to count, but the frames sent are broadcast probe
	// requests. Nothing is crafted for the station's session.
	result, err := lab.TransmitAndListen(ctx, ex.Transmit, listenerOf(ex), lab.Options{
		Interface: ex.Request.Interface,
		Frames:    frames,
		FrameCap:  min(meta.MaxFrames, ex.MaxFrames),
		ListenFor: observe,
		Summarize: describeFrame,
		Now:       ex.Now,
	})
	outcome := operation.Outcome{
		Notes:             []string{fmt.Sprintf("Broadcast %d probe request(s) on the authorized target and listened %s for frames it addressed to %s.", count, observe, station)},
		Limitations:       meta.Limitations,
		FramesTransmitted: result.FramesTransmitted,
		BytesTransmitted:  result.BytesTransmitted,
		CleanupRequired:   false,
		CleanupState:      models.CleanupNotRequired,
	}
	outcome.Evidence = append(outcome.Evidence, result.Evidence("wifi-management-probe", station))
	outcome.Limitations = append(outcome.Limitations, result.Limitations()...)

	if err != nil {
		return outcome, err
	}
	if result.ObserveError() != nil {
		return outcome, result.ObserveError()
	}

	// Count the frames the target addressed to the station during the window.
	// Their absence is not reported as a protection result: it is equally
	// consistent with an unassociated station and with nothing reaching the air.
	forwarded := 0
	for _, frame := range result.Frames {
		if frameFor(frame.Bytes, station) {
			forwarded++
		}
	}
	outcome.Notes = append(outcome.Notes,
		fmt.Sprintf("Observed %d frame(s) addressed to %s in a %s window.", forwarded, station, result.ListenedFor))

	if forwarded > 0 {
		outcome.Findings = []models.Finding{observationFinding(
			"WLAN-ACT-002",
			"Target forwarded frames addressed to the authorized station",
			"medium",
			models.SeverityMedium,
			models.ConfObserved,
			fmt.Sprintf("The authorized target emitted %d frame(s) addressed to %s after the probe burst. A station sees frames addressed to it, which is consistent with the access point not filtering or protecting them.", forwarded, station),
			station,
			"Seeing frames addressed to a station does not establish that protected management frames were accepted unauthenticated. A later association-phase check is required for that.",
			outcome.Evidence,
		)}
		return outcome, nil
	}
	outcome.Limitations = append(outcome.Limitations,
		"No frame addressed to the authorized station was observed. This is consistent with management frame protection, with the station not being associated, and with no frame having reached the air. It is not a negative result.")
	return outcome, nil
}

// authenticationProbe asks how the target answers an authentication request.
//
// It sends one authentication frame per algorithm and records the status code
// the target returned. The status code is reported verbatim: it says how the
// target answered, not whether the credential was correct.
type authenticationProbe struct{}

func (m *authenticationProbe) Meta() operation.Meta {
	return transmitCommon(
		ModuleWiFiAuthenticationProbe,
		"Probe Authentication Handling",
		"Transmit a bounded set of authentication frames to the authorized access point and report the status codes it returned.",
		"wifi-authentication-probe",
		[]operation.Parameter{
			{Name: "algorithm", Kind: "int", Description: "authentication algorithm number to request", Default: "0"},
			{Name: "count", Kind: "int", Description: "authentication frames to send", Default: "3"},
			{Name: "observe", Kind: "duration", Description: "listen window after transmitting", Default: "3s"},
		},
		nil,
		10,
		60*time.Second,
		[]string{
			"The access point is the authorized target.",
			"No credential is supplied: the probe uses the open system algorithm only.",
		},
		// Moderate noise: sends authentication frames which are more unusual than
		// normal client probing. A rapid sequence suggests testing rather than
		// legitimate client behavior.
		models.NoiseLevelModerate,
	)
}

func (m *authenticationProbe) Run(ctx context.Context, ex *operation.Execution) (operation.Outcome, error) {
	meta := m.Meta()
	source, err := requiredMAC(ex, meta, "source")
	if err != nil {
		return operation.Outcome{}, err
	}
	target, err := targetMAC(ex)
	if err != nil {
		return operation.Outcome{}, err
	}
	count, err := ex.Request.IntParam(meta, "count")
	if err != nil {
		return operation.Outcome{}, err
	}
	algorithm, err := ex.Request.IntParam(meta, "algorithm")
	if err != nil {
		return operation.Outcome{}, err
	}
	if algorithm < 0 || algorithm > 0xffff {
		return operation.Outcome{}, fmt.Errorf("parameter %q must be a 16-bit algorithm number, got %d", "algorithm", algorithm)
	}
	if count < 1 {
		return operation.Outcome{}, fmt.Errorf("parameter %q must be at least 1, got %d", "count", count)
	}
	observe, err := ex.Request.DurationParam(meta, "observe", lab.MaxListenWindow)
	if err != nil {
		return operation.Outcome{}, err
	}
	ceiling := min(meta.MaxFrames, ex.MaxFrames)
	if count > ceiling {
		return operation.Outcome{}, fmt.Errorf("parameter %q is %d, above the %d frame ceiling for this run", "count", count, ceiling)
	}

	frames := make([][]byte, 0, count)
	sequence := uint16(1)
	for index := 0; index < count; index++ {
		body, buildErr := wireless.BuildAuthentication(source, wireless.MACAddress{}, uint16(algorithm), 0, sequence)
		if buildErr != nil {
			return operation.Outcome{}, fmt.Errorf("build authentication frame %d: %w", index, buildErr)
		}
		frames = append(frames, append(wireless.RadiotapHeader(), body...))
		sequence = wireless.SequenceNumber(sequence)
	}
	bssid, _ := wireless.ParseMACAddress(target)

	result, err := lab.TransmitAndListen(ctx, ex.Transmit, listenerOf(ex), lab.Options{
		Interface: ex.Request.Interface,
		Frames:    frames,
		FrameCap:  ceiling,
		ListenFor: observe,
		Summarize: describeFrame,
		Now:       ex.Now,
	})
	outcome := operation.Outcome{
		Notes: []string{fmt.Sprintf("Transmitted %d authentication frame(s) requesting algorithm %d to %s and listened for %s.", count, algorithm, bssid, observe)},
		Limitations: append(meta.Limitations,
			"An authentication status code reports how the target answered the request. It does not establish whether a credential is correct, and no credential is supplied by this module."),
		FramesTransmitted: result.FramesTransmitted,
		BytesTransmitted:  result.BytesTransmitted,
		CleanupRequired:   false,
		CleanupState:      models.CleanupNotRequired,
	}
	outcome.Evidence = append(outcome.Evidence, result.Evidence("wifi-authentication-probe", target))
	outcome.Limitations = append(outcome.Limitations, result.Limitations()...)

	if err != nil {
		return outcome, err
	}
	if result.ObserveError() != nil {
		return outcome, result.ObserveError()
	}

	statuses := authenticationStatuses(result.Frames)
	if len(statuses) == 0 {
		outcome.Limitations = append(outcome.Limitations,
			"No authentication frame was observed in the listen window. This is consistent with the target ignoring the request, with protection dropping it, and with no frame having reached the air.")
		return outcome, nil
	}
	outcome.Notes = append(outcome.Notes,
		fmt.Sprintf("Observed %d authentication frame(s) with status code(s) %v.", len(statuses), statuses))

	outcome.Findings = []models.Finding{observationFinding(
		"WLAN-ACT-003",
		"Target answered an authentication request",
		"medium",
		models.SeverityMedium,
		models.ConfObserved,
		fmt.Sprintf("The authorized access point returned authentication status code(s) %v in response to an algorithm %d request. An access point that answers unauthenticated management requests is completing a step of the legacy handshake that later phases depend on.", statuses, algorithm),
		target,
		"An answered request does not establish that association, key establishment, or data access is permitted. Each is a separate step and must be assessed separately.",
		outcome.Evidence,
	)}
	return outcome, nil
}
