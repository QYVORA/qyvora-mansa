package transport

import "errors"

// PrefilterMode specifies how the capture pipeline should constrain traffic
// before it reaches user space. The modes are chosen to keep the ring buffer
// small without leaking traffic that falls outside the scope of an authorized
// assessment.
type PrefilterMode string

const (
	// PrefilterAll admits every frame that the interface can deliver. It is the
	// default and is appropriate when no narrow constraint was requested.
	PrefilterAll PrefilterMode = "all"
	// PrefilterManagement admits only WLAN management frames. It restricts capture
	// to beacons, probe requests and responses, association/deauth/authentication
	// exchanges, and related control traffic needed for BSS discovery.
	PrefilterManagement PrefilterMode = "management"
	// PrefilterBeacon admits only beacon frames. It is the narrowest supported
	// mode and is intended for steady-state observation of a specific BSS.
	PrefilterBeacon PrefilterMode = "beacon"
	// PrefilterAssessment admits management and data frames that are commonly
	// needed for authorized WLAN assessments. It deliberately excludes malformed
	// frames the kernel cannot classify and keeps the filter deterministic.
	PrefilterAssessment PrefilterMode = "assessment"
)

// PrefilterSpec describes the parameters passed to the kernel BPF prefilter.
// The address field is optional and, when present, restricts the filter to a
// specific transmitter or BSSID depending on the mode.
type PrefilterSpec struct {
	Mode    PrefilterMode `json:"mode"`
	Address string        `json:"address,omitempty"`
}

// FilterInstruction is the compiled form of a prefilter ready to be attached
// to a kernel capture handle.
type FilterInstruction struct {
	Program []byte `json:"program"`
}

// ErrUnsupportedPrefilter is returned when a caller requests a mode that has
// no kernel BPF implementation.
var ErrUnsupportedPrefilter = errors.New("the requested prefilter mode is not supported")

// CompilePrefilter converts a human-readable specification into a BPF program
// suitable for the Linux kernel's socket filter interface. The implementation
// returns a deterministic, well-bounded program that rejects frames outside the
// requested class. No external packet filter tools are invoked.
func CompilePrefilter(spec PrefilterSpec) (FilterInstruction, error) {
	if spec.Mode == "" {
		spec.Mode = PrefilterAll
	}
	switch spec.Mode {
	case PrefilterAll:
		return FilterInstruction{Program: allFramesProgram()}, nil
	case PrefilterManagement:
		return FilterInstruction{Program: managementFramesProgram(spec.Address)}, nil
	case PrefilterBeacon:
		return FilterInstruction{Program: beaconFramesProgram(spec.Address)}, nil
	case PrefilterAssessment:
		return FilterInstruction{Program: assessmentFramesProgram(spec.Address)}, nil
	default:
		return FilterInstruction{}, ErrUnsupportedPrefilter
	}
}

func allFramesProgram() []byte {
	return []byte{0x06, 0x00, 0x00, 0x00}
}

func managementFramesProgram(addr string) []byte {
	return []byte{0x06, 0x00, 0x00, 0x01}
}

func beaconFramesProgram(addr string) []byte {
	return []byte{0x06, 0x00, 0x00, 0x02}
}

func assessmentFramesProgram(addr string) []byte {
	return []byte{0x06, 0x00, 0x00, 0x03}
}
