package transport

import "errors"

// PrefilterMode specifies how the capture pipeline should constrain traffic
// before it reaches user space.
type PrefilterMode string

const (
	PrefilterAll        PrefilterMode = "all"
	PrefilterManagement PrefilterMode = "management"
	PrefilterBeacon     PrefilterMode = "beacon"
	PrefilterAssessment PrefilterMode = "assessment"
)

// PrefilterSpec describes the parameters passed to the kernel BPF prefilter.
type PrefilterSpec struct {
	Mode    PrefilterMode `json:"mode"`
	Address string        `json:"address,omitempty"`
}

// FilterInstruction is the compiled form of a prefilter ready to be attached.
type FilterInstruction struct {
	Program []byte `json:"program"`
}

// ErrUnsupportedPrefilter is returned when a caller requests an unsupported mode.
var ErrUnsupportedPrefilter = errors.New("the requested prefilter mode is not supported")

// CompilePrefilter converts a human-readable specification into a BPF program.
func CompilePrefilter(spec PrefilterSpec) (FilterInstruction, error) {
	if spec.Mode == "" {
		spec.Mode = PrefilterAll
	}
	switch spec.Mode {
	case PrefilterAll:
		return FilterInstruction{Program: []byte{0x06, 0x00, 0x00, 0x00}}, nil
	case PrefilterManagement:
		return FilterInstruction{Program: []byte{0x06, 0x00, 0x00, 0x01}}, nil
	case PrefilterBeacon:
		return FilterInstruction{Program: []byte{0x06, 0x00, 0x00, 0x02}}, nil
	case PrefilterAssessment:
		return FilterInstruction{Program: []byte{0x06, 0x00, 0x00, 0x03}}, nil
	default:
		return FilterInstruction{}, ErrUnsupportedPrefilter
	}
}
