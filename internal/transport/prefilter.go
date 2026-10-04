package transport

import (
	"errors"
	"fmt"
	"strings"
)

// PrefilterMode selects which captured frames a kernel prefilter keeps.
type PrefilterMode string

const (
	// PrefilterAll keeps every frame. It compiles to no program so the caller
	// never installs a socket filter.
	PrefilterAll PrefilterMode = "all"
	// PrefilterManagement keeps only 802.11 management frames.
	PrefilterManagement PrefilterMode = "management"
	// PrefilterBeacon keeps only 802.11 beacons.
	PrefilterBeacon PrefilterMode = "beacon"
	// PrefilterAssessment keeps every management frame plus unencrypted data
	// frames carrying an EAPOL payload. This is the default because an
	// assessment needs beacons, association metadata, and the four-way
	// handshake while discarding bulk traffic.
	PrefilterAssessment PrefilterMode = "assessment"
)

// PrefilterSpec describes the kernel-side prefilter to attach before binding.
type PrefilterSpec struct {
	Mode PrefilterMode
	// Filter, when set, is a single colon- or dash-separated MAC address.
	// Frames whose first or second address field in the 802.11 MAC header
	// matches are kept and every other frame is dropped.
	Filter string
}

// Captured link types Mansa understands. A prefilter must compile for the same
// link type the capture provider reports.
const (
	linkTypeIEEE80211Capture = 105
	linkTypeRadiotapCapture  = 127
)

// Enabled reports false when the prefilter accepts everything and therefore
// needs no kernel filter at all.
func (s PrefilterSpec) Enabled() bool {
	return s.Mode != "" && s.Mode != PrefilterAll
}

func (s PrefilterSpec) validate() (string, error) {
	switch s.Mode {
	case "", PrefilterAll, PrefilterManagement, PrefilterBeacon, PrefilterAssessment:
	default:
		return "", fmt.Errorf("unsupported prefilter mode %q", s.Mode)
	}
	filter := strings.TrimSpace(s.Filter)
	if filter == "" {
		return "", nil
	}
	filter = strings.ReplaceAll(filter, "-", ":")
	if err := validatePrefilterMAC(filter); err != nil {
		return "", err
	}
	return filter, nil
}

func validatePrefilterMAC(value string) error {
	groups := strings.Split(value, ":")
	if len(groups) != 6 {
		return fmt.Errorf("prefilter address %q must be a colon-separated MAC address", value)
	}
	for _, group := range groups {
		if len(group) != 2 {
			return fmt.Errorf("prefilter address %q must be a colon-separated MAC address", value)
		}
		for i := 0; i < len(group); i++ {
			c := group[i]
			switch {
			case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
			default:
				return fmt.Errorf("prefilter address %q must be a colon-separated MAC address", value)
			}
		}
	}
	return nil
}

// prefilterMACBytes converts a validated colon-separated address into the six
// octet values compared against the frame header.
func prefilterMACBytes(filter string) [6]uint32 {
	var out [6]uint32
	groups := strings.Split(filter, ":")
	for i := 0; i < 6 && i < len(groups); i++ {
		if len(groups[i]) != 2 {
			return out
		}
		out[i] = uint32(hexNibble(groups[i][0])<<4 | hexNibble(groups[i][1]))
	}
	return out
}

func hexNibble(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	default:
		return 0
	}
}

// FilterInstruction is one classic BPF instruction. It mirrors unix.SockFilter
// without importing a platform type so the compiler is testable on any host.
type FilterInstruction struct {
	Code uint16
	JT   uint8
	JF   uint8
	K    uint32
}

// Classic BPF opcode groups, sizes, and modifiers.
const (
	bpfLD   = 0x00
	bpfLDX  = 0x01
	bpfST   = 0x02
	bpfALU  = 0x04
	bpfJMP  = 0x05
	bpfRET  = 0x06
	bpfMISC = 0x07

	bpfW   = 0x00
	bpfB   = 0x10
	bpfH   = 0x08
	bpfIMM = 0x00
	bpfMEM = 0x60
	bpfABS = 0x20
	bpfIND = 0x40

	bpfAND = 0x50
	bpfOR  = 0x40
	bpfADD = 0x00
	bpfLSH = 0x60
	bpfTAX = 0x00

	bpfJA  = 0x00
	bpfJEQ = 0x10

	bpfK = 0x00
	bpfX = 0x08
)

// The kernel rejects classic BPF programs above these limits; Mansa refuses to
// emit one it cannot install.
const maxFilterInstructions = 4096

// Classic BPF jump encoding and verdicts.
const (
	bpfAccept = 0x00040000
	bpfDrop   = 0x00000000
)

// Scratch slots used by the emitted programs.
const (
	slotBase       = 0 // offset of the 802.11 MAC header within the packet
	slotFrameCtrl  = 4
	slotAccumulate = 8
)

// 802.11 frame control bit positions used by the emitted programs.
const (
	frameControlToDS    = 0x01
	frameControlFromDS  = 0x02
	frameControlHT      = 0x20
	frameControlType    = 0x0c
	frameControlSubtype = 0xf0

	frameTypeManagement = 0x00
	frameTypeData       = 0x08

	subtypeBeacon = 0x80

	// Data MAC header lengths by (ToDS, FromDS).
	macHeaderNoAddr4 = 24
	macHeaderToDS    = 26
	macHeaderFromDS  = 30
	macHeaderBothDS  = 36

	qosControlLength = 2
	htControlLength  = 4

	// The SNAP ether type occupies the last two bytes of the LLC header.
	snapEtherTypeOffset   = 6
	eapolSNAPFirstByte    = 0x88
	eapolSNAPSecondByte   = 0x8e
	addressFieldOneOffset = 4
	addressFieldTwoOffset = 10
)

var errFilterTooLarge = errors.New("compiled prefilter exceeds the classic BPF program limit")

type filterFixup struct {
	index  int
	label  string
	onTrue bool
}

// filterAssembler builds a classic BPF program with forward-referenced labels.
type filterAssembler struct {
	program  []FilterInstruction
	labels   map[string]int
	fixups   []filterFixup
	radiotap bool // the captured packet starts with a variable-length radiotap header
	mode     PrefilterMode
}

func newFilterAssembler(radiotap bool, mode PrefilterMode) *filterAssembler {
	return &filterAssembler{labels: map[string]int{}, radiotap: radiotap, mode: mode}
}

func (a *filterAssembler) emit(code uint16, k uint32) int {
	a.program = append(a.program, FilterInstruction{Code: code, K: k})
	return len(a.program) - 1
}

func (a *filterAssembler) bind(name string) {
	if _, ok := a.labels[name]; !ok {
		a.labels[name] = len(a.program)
	}
}

// jump emits a conditional jump whose true or false leg points at a label. The
// classic BPF interpreter advances past the jump word plus the selected offset.
func (a *filterAssembler) jump(code uint16, k uint32, target string, onTrue bool) {
	a.fixups = append(a.fixups, filterFixup{index: a.emit(bpfJMP|code, k), label: target, onTrue: onTrue})
}

func (a *filterAssembler) gotoLabel(target string) { a.jump(bpfJA, 0, target, true) }

func (a *filterAssembler) loadK(k uint32)          { a.emit(bpfLD|bpfW|bpfIMM, k) }
func (a *filterAssembler) store(slot int)          { a.emit(bpfST|bpfW|bpfMEM, uint32(slot)) }
func (a *filterAssembler) loadSlot(slot int)       { a.emit(bpfLD|bpfW|bpfMEM, uint32(slot)) }
func (a *filterAssembler) transferAtoX()           { a.emit(bpfMISC|bpfTAX, 0) }
func (a *filterAssembler) and(k uint32)            { a.alu(bpfAND, k) }
func (a *filterAssembler) alu(op uint16, k uint32) { a.emit(bpfALU|op, k) }

// aluRegX applies an operation whose operand is the index register. The BPF_X
// modifier belongs in the opcode, not in K; putting it in K would silently
// substitute the constant for the register value.
func (a *filterAssembler) aluRegX(op uint16) { a.emit(bpfALU|op|bpfX, 0) }
func (a *filterAssembler) ret(k uint32)      { a.emit(bpfRET|bpfK, k) }

// loadPacketByte reads a byte at an offset from the start of the captured
// packet, which for the radiotap link type still includes the radiotap header.
func (a *filterAssembler) loadPacketByte(offset uint32) { a.emit(bpfLD|bpfB|bpfABS, offset) }

// loadMacByte reads a byte at a constant offset from the address held in X. The
// caller decides what X holds: the MAC header offset for frame fields, or the
// LLC header offset for the SNAP ether type. Every 802.11 field access is
// indirect because the captured layout starts at an offset that is not known
// when the program is compiled.
func (a *filterAssembler) loadMacByte(offset uint32) { a.emit(bpfLD|bpfB|bpfIND, offset) }

func (a *filterAssembler) finish() ([]FilterInstruction, error) {
	if len(a.program) > maxFilterInstructions {
		return nil, errFilterTooLarge
	}
	resolved := make([]FilterInstruction, len(a.program))
	copy(resolved, a.program)
	for _, fixup := range a.fixups {
		target, ok := a.labels[fixup.label]
		if !ok {
			return nil, fmt.Errorf("prefilter references undefined label %q", fixup.label)
		}
		offset := target - (fixup.index + 1)
		if offset < 0 || offset > 255 {
			return nil, fmt.Errorf("prefilter jump to %q exceeds the 8-bit offset", fixup.label)
		}
		if fixup.onTrue {
			resolved[fixup.index].JT = uint8(offset)
		} else {
			resolved[fixup.index].JF = uint8(offset)
		}
	}
	return resolved, nil
}

// CompilePrefilter builds a classic BPF program for the supplied spec. The
// program is generated and verified in-tree; Mansa never shells out to an
// external packet filter compiler.
//
// linkType selects the captured byte layout. The radiotap link type hides a
// variable-length header ahead of the 802.11 MAC header, so the program derives
// that offset per packet. The plain 802.11 link type starts at the MAC header.
func CompilePrefilter(linkType uint32, spec PrefilterSpec) ([]FilterInstruction, error) {
	if !spec.Enabled() {
		return nil, nil
	}
	filter, err := spec.validate()
	if err != nil {
		return nil, err
	}
	a := newFilterAssembler(linkType == linkTypeRadiotapCapture, spec.Mode)
	a.emitBaseOffset()
	a.emitFrameClassification(filter)

	const accept = "verdict_accept"
	const drop = "verdict_drop"
	a.bind(accept)
	a.ret(bpfAccept)
	a.bind(drop)
	a.ret(bpfDrop)
	return a.finish()
}

// emitBaseOffset stores the offset of the 802.11 MAC header in slotBase.
func (a *filterAssembler) emitBaseOffset() {
	if !a.radiotap {
		a.loadK(0)
		a.store(slotBase)
		return
	}
	// The radiotap header length is a 16-bit little-endian value at offset 2 and
	// no load instruction reads a little-endian halfword, so swap the bytes by
	// hand: a halfword load already yields P[2]<<8|P[3].
	a.emit(bpfLD|bpfH|bpfABS, 2)
	a.transferAtoX()
	a.alu(bpfAND, 0x00ff)
	a.alu(bpfLSH, 8)
	a.transferAtoX()
	a.loadPacketByte(2)
	a.aluRegX(bpfOR)
	a.transferAtoX()
	a.store(slotBase)
}

// loadBaseIntoX moves slotBase into the index register.
func (a *filterAssembler) loadBaseIntoX() { a.emit(bpfLDX|bpfW|bpfMEM, uint32(slotBase)) }

func (a *filterAssembler) emitFrameClassification(filter string) {
	const accept = "verdict_accept"
	const drop = "verdict_drop"
	const manage = "branch_management"
	const data = "branch_data"
	const gate = "branch_address_gate"

	// Address the 802.11 MAC header. The data branch recomputes X because the
	// frame type is already known by then.
	a.loadBaseIntoX()
	a.loadMacByte(0)
	a.and(frameControlType)
	a.jump(bpfJEQ, frameTypeManagement, manage, true)
	a.jump(bpfJEQ, frameTypeData, data, true)
	a.gotoLabel(drop)

	// Every management frame survives, except that beacon mode keeps only
	// beacons and any mode with an address filter must still match.
	a.bind(manage)
	switch a.mode {
	case PrefilterManagement, PrefilterAssessment:
		a.gotoLabel(gate)
	case PrefilterBeacon:
		a.loadMacByte(0)
		a.and(frameControlSubtype)
		a.jump(bpfJEQ, subtypeBeacon, gate, true)
		a.gotoLabel(drop)
	}

	// The data branch survives only in assessment mode, and only for EAPOL.
	a.bind(data)
	if a.mode != PrefilterAssessment {
		a.gotoLabel(drop)
	}
	a.emitEAPOLMatch(gate)

	// An optional single-address restriction. Address fields one and two always
	// follow the fixed duration field, so they sit at constant offsets relative
	// to the MAC header in every frame type.
	a.bind(gate)
	if filter == "" {
		a.gotoLabel(accept)
		return
	}
	a.emitAddressMatch(filter, accept, drop)
}

// emitEAPOLMatch keeps a data frame only when its SNAP ether type is EAPOL.
func (a *filterAssembler) emitEAPOLMatch(next string) {
	const missed = "eapol_missed"
	const drop = "verdict_drop"

	// The first two frame control bits select the data MAC header layout.
	a.loadBaseIntoX()
	a.loadMacByte(0)
	a.store(slotFrameCtrl)
	a.and(frameControlToDS | frameControlFromDS)
	a.jump(bpfJEQ, 0, "hdr_plain", true)
	a.jump(bpfJEQ, frameControlToDS, "hdr_to_ds", true)
	a.jump(bpfJEQ, frameControlFromDS, "hdr_from_ds", true)
	a.bind("hdr_both_ds")
	a.loadK(macHeaderBothDS)
	a.gotoLabel("hdr_extended")

	a.bind("hdr_plain")
	a.loadK(macHeaderNoAddr4)
	a.gotoLabel("hdr_extended")
	a.bind("hdr_to_ds")
	a.loadK(macHeaderToDS)
	a.gotoLabel("hdr_extended")
	a.bind("hdr_from_ds")
	a.loadK(macHeaderFromDS)

	// A QoS Control field is present when the data subtype is 8 through 15, and
	// an HT Control field is present when the order bit is set. Each extends the
	// MAC header, so accumulate both into the same slot.
	a.bind("hdr_extended")
	a.store(slotAccumulate)

	a.loadSlot(slotFrameCtrl)
	a.and(frameControlSubtype)
	a.jump(bpfJEQ, 0, "hdr_ht_check", true)
	a.loadSlot(slotAccumulate)
	a.alu(bpfADD, qosControlLength)
	a.store(slotAccumulate)

	a.bind("hdr_ht_check")
	a.loadSlot(slotFrameCtrl)
	a.and(frameControlHT)
	a.jump(bpfJEQ, 0, "hdr_accumulated", true)
	a.loadSlot(slotAccumulate)
	a.alu(bpfADD, htControlLength)
	a.store(slotAccumulate)

	// Accumulate the MAC header length over the radiotap offset, then compare
	// the SNAP ether type.
	a.bind("hdr_accumulated")
	a.loadBaseIntoX()
	a.loadSlot(slotAccumulate)
	a.aluRegX(bpfADD)
	a.transferAtoX()
	a.loadMacByte(snapEtherTypeOffset)
	a.jump(bpfJEQ, eapolSNAPFirstByte, "eapol_second", true)
	a.gotoLabel(missed)
	a.bind("eapol_second")
	a.loadMacByte(snapEtherTypeOffset + 1)
	a.jump(bpfJEQ, eapolSNAPSecondByte, next, true)

	a.bind(missed)
	a.gotoLabel(drop)
}

// emitAddressMatch keeps a frame when address field one or two equals the
// requested MAC address. Each field is compared as a straight-line chain: a
// matching byte falls through to the next byte, and the first differing byte
// abandons the field. Every exit leaves X at the MAC header offset so the
// EAPOL branch can reuse it.
func (a *filterAssembler) emitAddressMatch(filter, accept, drop string) {
	want := prefilterMACBytes(filter)
	// The EAPOL branch leaves X on the LLC header, so restore the MAC header
	// offset before reading any address field.
	a.loadBaseIntoX()
	for _, field := range []uint32{addressFieldOneOffset, addressFieldTwoOffset} {
		abandon := fmt.Sprintf("addr_abandon_%d", field)
		for i := uint32(0); i < 6; i++ {
			a.loadMacByte(field + i)
			a.jump(bpfJEQ, want[i], abandon, false)
		}
		// All six bytes matched this field.
		a.gotoLabel(accept)
		a.bind(abandon)
	}
	a.gotoLabel(drop)
}
