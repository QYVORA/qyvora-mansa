package transport

import (
	"errors"
	"fmt"
	"strings"

	"github.com/QYVORA/qyvora-mansa/internal/wireless"
)

// The link-layer formats a capture socket can report. They match the libpcap
// DLT values Linux uses for ARPHRD_IEEE80211 and ARPHRD_IEEE80211_RADIOTAP.
const (
	linkTypeIEEE80211Capture uint32 = 105
	linkTypeRadiotapCapture  uint32 = 127
)

// maxFilterInstructions is the kernel's classic BPF program limit, BPF_MAXINSNS.
const maxFilterInstructions = 4096

// bpfAccept is the return value libpcap uses to keep a packet; anything else
// drops it.
const bpfAccept = 0x00010000

// Classic BPF opcodes. The verifier in the kernel masks the code word to pick
// out the class, size, mode, operation, and source operand, so the encodings
// below have to keep the conventional bit positions.
const (
	bpfLD   uint16 = 0x00
	bpfLDX  uint16 = 0x01
	bpfST   uint16 = 0x02
	bpfALU  uint16 = 0x04
	bpfJMP  uint16 = 0x05
	bpfRET  uint16 = 0x06
	bpfMISC uint16 = 0x07

	bpfW uint16 = 0x00
	bpfH uint16 = 0x08
	bpfB uint16 = 0x10

	bpfIMM uint16 = 0x00
	bpfABS uint16 = 0x20
	bpfIND uint16 = 0x40
	bpfMEM uint16 = 0x60

	bpfADD uint16 = 0x00
	bpfOR  uint16 = 0x40
	bpfAND uint16 = 0x50
	bpfLSH uint16 = 0x60

	bpfTAX uint16 = 0x00

	bpfJA  uint16 = 0x00
	bpfJEQ uint16 = 0x10

	bpfSourceK uint16 = 0x00
	bpfSourceX uint16 = 0x08
)

// 802.11 frame layout constants the compiled filters depend on.
const (
	frameControlToDS        = 0x01
	frameControlFromDS      = 0x02
	frameControlTypeMask    = 0x0c
	frameControlSubtypeMask = 0xf0

	// frameControlSubtype is the frame control mask that isolates the subtype.
	frameControlSubtype = frameControlSubtypeMask

	// typeManagement and typeData are the frame type field shifted into place,
	// that is already aligned with frameControlTypeMask.
	typeManagement = 0x00
	typeData       = 0x08

	// subtypeBeacon is the beacon subtype in unshifted form, for comparison
	// against a masked frame control byte.
	subtypeBeacon = 8

	// frameControlQOSBit is set on every subtype that carries the two byte QoS
	// control field, which is what decides whether the LLC header moves.
	frameControlQOSBit = 0x80

	macHeaderNoAddr4 = 24
	macHeaderToDS    = 30
	macHeaderFromDS  = 24
	macHeaderBothDS  = 30

	qosControlLength = 2

	// transmitterAddressOffset is the 802.11 address 2 field, the source
	// address in every frame type this filter inspects.
	transmitterAddressOffset = 10

	// snapEtherTypeOffset is the position of the ethertype inside an 802.11
	// data frame's LLC/SNAP header.
	snapEtherTypeOffset = 6

	// etherTypeEAPOL is the only payload an assessment retains from data frames.
	etherTypeEAPOL = 0x888e

	// radiotapLengthOffset holds the little endian header length of a radiotap
	// header.
	radiotapLengthOffset = 2
)

// FilterInstruction is one classic BPF instruction.
type FilterInstruction struct {
	Code uint16 `json:"code"`
	JT   uint8  `json:"jt"`
	JF   uint8  `json:"jf"`
	K    uint32 `json:"k"`
}

// PrefilterMode specifies how the capture pipeline should constrain traffic
// before it reaches user space.
type PrefilterMode string

const (
	// PrefilterAll captures everything and installs no kernel filter.
	PrefilterAll PrefilterMode = "all"
	// PrefilterManagement retains management frames.
	PrefilterManagement PrefilterMode = "management"
	// PrefilterBeacon retains beacons only.
	PrefilterBeacon PrefilterMode = "beacon"
	// PrefilterAssessment retains management frames plus EAPOL handshakes.
	PrefilterAssessment PrefilterMode = "assessment"
)

// PrefilterSpec describes the parameters passed to the kernel BPF prefilter.
type PrefilterSpec struct {
	Mode   PrefilterMode `json:"mode"`
	Filter string        `json:"filter,omitempty"`
}

// ErrUnsupportedPrefilter is returned when a caller requests an unsupported mode
// or link type.
var ErrUnsupportedPrefilter = errors.New("the requested prefilter mode is not supported")

// Enabled reports whether the spec asks for a kernel filter at all. The all mode
// and the zero value both leave the socket unfiltered.
func (s PrefilterSpec) Enabled() bool {
	switch s.Mode {
	case PrefilterAssessment, PrefilterManagement, PrefilterBeacon:
		return true
	default:
		return false
	}
}

// validate checks the spec and returns the address in canonical form.
func (s PrefilterSpec) validate() (string, error) {
	normalized, _, err := s.parts()
	return normalized, err
}

// parts validates the spec and returns the canonical address together with its
// octets.
func (s PrefilterSpec) parts() (string, [6]byte, error) {
	var mac [6]byte
	switch s.Mode {
	case PrefilterAssessment, PrefilterManagement, PrefilterBeacon, PrefilterAll, "":
	default:
		return "", mac, ErrUnsupportedPrefilter
	}
	if s.Filter == "" {
		return "", mac, nil
	}
	parsed, err := wireless.ParseMACAddress(s.Filter)
	if err != nil {
		return "", mac, err
	}
	copy(mac[:], parsed[:])
	return strings.ReplaceAll(s.Filter, "-", ":"), mac, nil
}

// filterAssembler builds a classic BPF program with symbolic jump targets so
// the emitted instruction offsets stay correct when the program is rearranged.
type filterAssembler struct {
	instructions []FilterInstruction
	labels       map[string]int
	pending      []filterJump
}

type filterJump struct {
	index       int
	target      string
	conditional bool
}

func newFilterAssembler() *filterAssembler {
	return &filterAssembler{labels: map[string]int{}}
}

func (a *filterAssembler) emit(in FilterInstruction) {
	a.instructions = append(a.instructions, in)
}

// jumpTo emits an unconditional jump.
func (a *filterAssembler) jumpTo(target string) {
	a.emit(FilterInstruction{Code: bpfJMP | bpfJA})
	a.pending = append(a.pending, filterJump{index: len(a.instructions) - 1, target: target})
}

// equalTo emits a conditional jump taken when the accumulator matches. The
// false path falls through to the next instruction.
func (a *filterAssembler) equalTo(value uint32, target string) {
	a.emit(FilterInstruction{Code: bpfJMP | bpfJEQ | bpfSourceK, K: value})
	a.pending = append(a.pending, filterJump{
		index:       len(a.instructions) - 1,
		target:      target,
		conditional: true,
	})
}

func (a *filterAssembler) mark(name string) {
	a.labels[name] = len(a.instructions)
}

// assemble resolves the symbolic jump targets. Every jump in these filters is
// forward, and the kernel encodes the distance in the instruction word.
func (a *filterAssembler) assemble() ([]FilterInstruction, error) {
	for _, jump := range a.pending {
		target, ok := a.labels[jump.target]
		if !ok {
			return nil, fmt.Errorf("prefilter jump target %q was never marked", jump.target)
		}
		distance := target - (jump.index + 1)
		if distance < 0 || distance > 255 {
			return nil, fmt.Errorf("prefilter jump to %q is %d instructions away", jump.target, distance)
		}
		a.instructions[jump.index].JT = uint8(distance)
		if !jump.conditional {
			// Only an unconditional jump uses both fields; a conditional
			// leaves a zero false offset so the next instruction runs.
			a.instructions[jump.index].JF = uint8(distance)
		}
	}
	if len(a.instructions) == 0 || len(a.instructions) > maxFilterInstructions {
		return nil, fmt.Errorf("prefilter is %d instructions long", len(a.instructions))
	}
	return a.instructions, nil
}

func loadAbs(size uint16, offset uint32) FilterInstruction {
	return FilterInstruction{Code: bpfLD | size | bpfABS, K: offset}
}

func loadInd(size uint16, offset uint32) FilterInstruction {
	return FilterInstruction{Code: bpfLD | size | bpfIND, K: offset}
}

func loadImm(value uint32) FilterInstruction {
	return FilterInstruction{Code: bpfLD | bpfW | bpfIMM, K: value}
}

func loadMem(slot uint32) FilterInstruction {
	return FilterInstruction{Code: bpfLD | bpfW | bpfMEM, K: slot}
}

func storeMem(slot uint32) FilterInstruction {
	return FilterInstruction{Code: bpfST | bpfW | bpfMEM, K: slot}
}

func aluAnd(value uint32) FilterInstruction {
	return FilterInstruction{Code: bpfALU | bpfAND | bpfSourceK, K: value}
}

func shiftLeftImm(bits uint32) FilterInstruction {
	return FilterInstruction{Code: bpfALU | bpfLSH | bpfSourceK, K: bits}
}

func addRegister() FilterInstruction {
	return FilterInstruction{Code: bpfALU | bpfADD | bpfSourceX}
}

func verdict(value uint32) FilterInstruction {
	return FilterInstruction{Code: bpfRET | bpfSourceK, K: value}
}

// startFrame places the first byte of the 802.11 frame in the X register so the
// rest of the program can address the frame independently of the link type. A
// radiotap capture carries a variable length header whose size is only known at
// run time, so the offset is read from the packet itself.
func (a *filterAssembler) startFrame(linkType uint32) {
	if linkType == linkTypeRadiotapCapture {
		// Classic BPF has no little endian half load, so the header length is
		// reassembled from its two bytes with a shift and an add.
		a.emit(loadAbs(bpfB, radiotapLengthOffset+1))
		a.emit(shiftLeftImm(8))
		a.emit(FilterInstruction{Code: bpfMISC | bpfTAX})
		a.emit(loadAbs(bpfB, radiotapLengthOffset))
		a.emit(addRegister())
	} else {
		a.emit(loadImm(0))
	}
	a.emit(FilterInstruction{Code: bpfMISC | bpfTAX})
	a.emit(storeMem(1))
}

// requireTransmitter drops every frame whose address 2 is not the requested
// station. Address 2 sits at the same offset in management and data frames, so
// one comparison covers both. A frame that matches continues at frameBody.
func (a *filterAssembler) requireTransmitter(mac [6]byte) {
	high := uint32(mac[0])<<24 | uint32(mac[1])<<16 | uint32(mac[2])<<8 | uint32(mac[3])
	low := uint32(mac[4])<<8 | uint32(mac[5])
	a.emit(loadInd(bpfW, transmitterAddressOffset))
	a.equalTo(high, "transmitterLow")
	a.jumpTo("drop")
	a.mark("transmitterLow")
	a.emit(loadInd(bpfH, transmitterAddressOffset+4))
	a.equalTo(low, "frameBody")
	a.jumpTo("drop")
}

// keepManagement retains management frames and drops everything else.
func (a *filterAssembler) keepManagement() {
	a.mark("frameBody")
	a.emit(loadInd(bpfB, 0))
	a.emit(aluAnd(frameControlTypeMask))
	a.equalTo(typeManagement, "accept")
	a.jumpTo("drop")
}

// keepBeacons retains beacons and drops everything else. Subtype 8 also names
// QoS data, so the frame type has to be inspected as well.
func (a *filterAssembler) keepBeacons() {
	a.mark("frameBody")
	a.emit(loadInd(bpfB, 0))
	a.emit(storeMem(0))
	a.emit(loadMem(0))
	a.emit(aluAnd(frameControlTypeMask))
	a.equalTo(typeManagement, "beaconSubtype")
	a.jumpTo("drop")
	a.mark("beaconSubtype")
	a.emit(loadMem(0))
	a.emit(aluAnd(frameControlSubtypeMask))
	a.equalTo(subtypeBeacon<<4, "accept")
	a.jumpTo("drop")
}

// keepAssessment retains every management frame and the EAPOL handshakes in
// data frames. Only then is the packet long enough to read the LLC header, so
// the payload offset is resolved by branching rather than loading speculatively.
func (a *filterAssembler) keepAssessment() {
	a.mark("frameBody")
	a.emit(loadInd(bpfB, 0))
	a.emit(storeMem(0))
	a.emit(loadMem(0))
	a.emit(aluAnd(frameControlTypeMask))
	a.equalTo(typeManagement, "accept")
	a.equalTo(typeData, "dataFrame")
	a.jumpTo("drop")

	a.mark("dataFrame")
	// Address 4 is present only when ToDS is set, and the QoS control field
	// shifts the header by two bytes, so four payload offsets are possible.
	a.emit(loadMem(0))
	a.emit(aluAnd(frameControlToDS))
	a.equalTo(frameControlToDS, "toDS")
	a.emit(loadMem(0))
	a.emit(aluAnd(frameControlQOSBit))
	a.equalTo(frameControlQOSBit, "llcQoSPlain")
	a.jumpTo("llcPlain")

	a.mark("toDS")
	a.emit(loadMem(0))
	a.emit(aluAnd(frameControlQOSBit))
	a.equalTo(frameControlQOSBit, "llcQoSToDS")
	a.jumpTo("llcToDS")

	for _, llc := range []struct {
		name   string
		offset uint32
	}{
		{"llcPlain", macHeaderNoAddr4 + snapEtherTypeOffset},
		{"llcQoSPlain", macHeaderNoAddr4 + qosControlLength + snapEtherTypeOffset},
		{"llcToDS", macHeaderToDS + snapEtherTypeOffset},
		{"llcQoSToDS", macHeaderToDS + qosControlLength + snapEtherTypeOffset},
	} {
		a.mark(llc.name)
		a.emit(loadInd(bpfH, llc.offset))
		a.equalTo(etherTypeEAPOL, "accept")
		a.jumpTo("drop")
	}
}

// end writes the two verdicts every compiled filter finishes with.
func (a *filterAssembler) end() {
	a.mark("accept")
	a.emit(verdict(bpfAccept))
	a.mark("drop")
	a.emit(verdict(0))
}

// CompilePrefilter converts a specification into a classic BPF program for the
// supplied link type. A spec that installs no filter compiles to no program at
// all, which lets the caller leave the socket untouched.
func CompilePrefilter(linkType uint32, spec PrefilterSpec) ([]FilterInstruction, error) {
	_, mac, err := spec.parts()
	if err != nil {
		return nil, err
	}
	if linkType != linkTypeIEEE80211Capture && linkType != linkTypeRadiotapCapture {
		return nil, ErrUnsupportedPrefilter
	}
	if !spec.Enabled() {
		return nil, nil
	}

	assembler := newFilterAssembler()
	assembler.startFrame(linkType)
	if spec.Filter != "" {
		assembler.requireTransmitter(mac)
	}
	switch spec.Mode {
	case PrefilterManagement:
		assembler.keepManagement()
	case PrefilterBeacon:
		assembler.keepBeacons()
	case PrefilterAssessment:
		assembler.keepAssessment()
	default:
		return nil, ErrUnsupportedPrefilter
	}
	assembler.end()
	return assembler.assemble()
}
