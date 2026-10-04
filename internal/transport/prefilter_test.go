package transport

import (
	"testing"

	"github.com/QYVORA/qyvora-mansa/internal/wireless"
)

// runClassicBPF interprets a compiled classic BPF program exactly as the kernel
// filter machine does. Verifying behaviour against real frames is stronger than
// asserting on instruction bytes, and it needs no adapter or privileges.
func runClassicBPF(t *testing.T, program []FilterInstruction, packet []byte) bool {
	t.Helper()
	var a, x uint32
	memory := make([]uint32, 16)
	pc := 0
	for step := 0; step < maxFilterInstructions; step++ {
		if pc < 0 || pc >= len(program) {
			t.Fatalf("program counter %d left the program of %d instructions", pc, len(program))
		}
		in := program[pc]
		load := func(size uint16, source uint16, k uint32) uint32 {
			switch source {
			case bpfIMM:
				return k
			case bpfMEM:
				return memory[k]
			case bpfABS, bpfIND:
				offset := k
				if source == bpfIND {
					offset += x
				}
				if offset >= uint32(len(packet)) {
					t.Fatalf("out-of-bounds load at %d of a %d byte packet", offset, len(packet))
				}
				switch size {
				case bpfB:
					return uint32(packet[offset])
				case bpfH:
					return uint32(packet[offset])<<8 | uint32(packet[offset+1])
				default:
					return uint32(packet[offset])<<24 | uint32(packet[offset+1])<<16 |
						uint32(packet[offset+2])<<8 | uint32(packet[offset+3])
				}
			}
			t.Fatalf("unsupported load source %#x", source)
			return 0
		}
		alu := func(op uint16, k uint32) {
			switch op {
			case bpfADD:
				a += k
			case bpfAND:
				a &= k
			case bpfOR:
				a |= k
			case bpfLSH:
				a <<= k & 31
			default:
				t.Fatalf("unsupported ALU operation %#x", op)
			}
		}
		compare := func(code uint16, k uint32) bool {
			if code&0x08 != 0 {
				return a == x
			}
			return a == k
		}
		switch in.Code & 0x07 {
		case bpfLD, bpfLDX:
			value := load(in.Code&0x18, in.Code&0xe0, in.K)
			if in.Code&0x07 == bpfLDX {
				x = value
			} else {
				a = value
			}
		case bpfST:
			memory[in.K] = a
		case bpfALU:
			operand := in.K
			if in.Code&0x08 != 0 {
				operand = x
			}
			alu(in.Code&0xf0, operand)
		case bpfMISC:
			if in.Code&0xf8 == bpfTAX {
				x = a
			} else {
				t.Fatalf("unsupported MISC operation %#x", in.Code)
			}
		case bpfJMP:
			if in.Code&0xf0 == bpfJA {
				pc += int(in.JT) + 1
				continue
			}
			matched := compare(in.Code, uint32(in.K))
			if matched {
				pc += int(in.JT) + 1
			} else {
				pc += int(in.JF) + 1
			}
			continue
		case bpfRET:
			return in.K == bpfAccept
		default:
			t.Fatalf("unsupported instruction class %#x", in.Code&0x07)
		}
		pc++
	}
	t.Fatal("prefilter did not reach a verdict within the instruction limit")
	return false
}

// 802.11 frame control helpers for the fixtures below.
const (
	fcBeacon        = 0x80
	fcProbeRequest  = 0x40
	fcDeauth        = 0xa0
	fcAssocRequest  = 0x00
	fcDataPlain     = 0x08
	fcDataQoS       = 0x88
	fcDataQoSFromDS = 0x8a
	fcDataQoSToDS   = 0x89
)

func managementFrame(t *testing.T, control byte, address string) []byte {
	t.Helper()
	frame := make([]byte, 24)
	frame[0] = control
	copy(frame[4:10], mustMACBytes(t, "aa:bb:cc:dd:ee:01"))
	copy(frame[10:16], mustMACBytes(t, address))
	copy(frame[16:22], mustMACBytes(t, "aa:bb:cc:dd:ee:01"))
	return frame
}

// dataFrame builds a data frame whose MAC header length follows the ToDS/FromDS
// bits and the QoS control field, then appends the supplied LLC payload.
func dataFrame(t *testing.T, control byte, llc []byte) []byte {
	t.Helper()
	length := macHeaderNoAddr4
	toDS := control&frameControlToDS != 0
	fromDS := control&frameControlFromDS != 0
	switch {
	case toDS && fromDS:
		length = macHeaderBothDS
	case toDS:
		length = macHeaderToDS
	case fromDS:
		length = macHeaderFromDS
	}
	if control&frameControlSubtype >= subtypeBeacon {
		length += qosControlLength
	}
	frame := make([]byte, length)
	frame[0] = control
	copy(frame[4:10], mustMACBytes(t, "aa:bb:cc:dd:ee:01"))
	copy(frame[10:16], mustMACBytes(t, "aa:bb:cc:dd:ee:02"))
	return append(frame, llc...)
}

func snap(etherType uint16) []byte {
	return []byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, byte(etherType >> 8), byte(etherType)}
}

// wrapRadiotap prefixes a frame with a version 0 radiotap header of the given
// length, which must be a multiple of four as the specification requires.
func wrapRadiotap(frame []byte, length int) []byte {
	header := make([]byte, length)
	header[0] = 0
	header[1] = 0
	header[2] = byte(length)
	header[3] = byte(length >> 8)
	return append(header, frame...)
}

func mustMACBytes(t *testing.T, value string) []byte {
	t.Helper()
	parsed, err := wireless.ParseMACAddress(value)
	if err != nil {
		t.Fatalf("parse %q: %v", value, err)
	}
	return parsed[:]
}

const testTarget = "de:ad:be:ef:00:01"

func TestCompilePrefilterRejectsUnsupportedInput(t *testing.T) {
	if _, err := CompilePrefilter(linkTypeIEEE80211Capture, PrefilterSpec{Mode: "nonsense"}); err == nil {
		t.Fatal("expected an unsupported mode to be rejected")
	}
	for _, bad := range []string{"de:ad:be:ef:00", "zz:ad:be:ef:00:01", "de:ad:be:ef:00:01:02", "deadbeef0001"} {
		if _, err := CompilePrefilter(linkTypeIEEE80211Capture, PrefilterSpec{Mode: PrefilterAssessment, Filter: bad}); err == nil {
			t.Fatalf("expected address %q to be rejected", bad)
		}
	}
	if program, err := CompilePrefilter(linkTypeIEEE80211Capture, PrefilterSpec{Mode: PrefilterAll, Filter: testTarget}); err != nil || program != nil {
		t.Fatalf("expected no program for the all mode, got %v %v", program, err)
	}
	if program, err := CompilePrefilter(linkTypeIEEE80211Capture, PrefilterSpec{}); err != nil || program != nil {
		t.Fatalf("expected no program for the default mode, got %v %v", program, err)
	}
}

// TestPrefilterSemantics runs every compiled program against real 802.11 frames
// for both supported link types. The expected verdicts are stated as the
// assessment, management, and beacon modes require.
func TestPrefilterSemantics(t *testing.T) {
	eapol := snap(0x888e)
	ipv4 := snap(0x0800)
	arp := snap(0x0806)
	const keep = true
	const drop = false

	cases := []struct {
		name     string
		packet   []byte
		expected map[PrefilterMode]bool
	}{
		{
			name:   "beacon",
			packet: managementFrame(t, fcBeacon, "de:ad:be:ef:00:01"),
			expected: map[PrefilterMode]bool{
				PrefilterAssessment: keep, PrefilterManagement: keep, PrefilterBeacon: keep,
			},
		},
		{
			name:   "probe request",
			packet: managementFrame(t, fcProbeRequest, "de:ad:be:ef:00:01"),
			expected: map[PrefilterMode]bool{
				PrefilterAssessment: keep, PrefilterManagement: keep, PrefilterBeacon: drop,
			},
		},
		{
			name:   "deauthentication",
			packet: managementFrame(t, fcDeauth, "de:ad:be:ef:00:01"),
			expected: map[PrefilterMode]bool{
				PrefilterAssessment: keep, PrefilterManagement: keep, PrefilterBeacon: drop,
			},
		},
		{
			name:   "association request",
			packet: managementFrame(t, fcAssocRequest, "de:ad:be:ef:00:01"),
			expected: map[PrefilterMode]bool{
				PrefilterAssessment: keep, PrefilterManagement: keep, PrefilterBeacon: drop,
			},
		},
		{
			name:   "qos data with EAPOL from the access point",
			packet: dataFrame(t, fcDataQoSFromDS, eapol),
			expected: map[PrefilterMode]bool{
				PrefilterAssessment: keep, PrefilterManagement: drop, PrefilterBeacon: drop,
			},
		},
		{
			name:   "qos data with EAPOL to the access point",
			packet: dataFrame(t, fcDataQoSToDS, eapol),
			expected: map[PrefilterMode]bool{
				PrefilterAssessment: keep, PrefilterManagement: drop, PrefilterBeacon: drop,
			},
		},
		{
			name:   "plain data with EAPOL",
			packet: dataFrame(t, fcDataPlain, eapol),
			expected: map[PrefilterMode]bool{
				PrefilterAssessment: keep, PrefilterManagement: drop, PrefilterBeacon: drop,
			},
		},
		{
			name:   "qos data with IPv4",
			packet: dataFrame(t, fcDataQoSFromDS, ipv4),
			expected: map[PrefilterMode]bool{
				PrefilterAssessment: drop, PrefilterManagement: drop, PrefilterBeacon: drop,
			},
		},
		{
			name:   "plain data with ARP",
			packet: dataFrame(t, fcDataPlain, arp),
			expected: map[PrefilterMode]bool{
				PrefilterAssessment: drop, PrefilterManagement: drop, PrefilterBeacon: drop,
			},
		},
		{
			name:   "data frame from an unrelated station",
			packet: dataFrame(t, fcDataPlain, eapol),
			expected: map[PrefilterMode]bool{
				PrefilterAssessment: keep, PrefilterManagement: drop, PrefilterBeacon: drop,
			},
		},
	}

	for _, linkType := range []uint32{linkTypeIEEE80211Capture, linkTypeRadiotapCapture} {
		// A radiotap capture always carries a radiotap header, so the zero
		// length case only applies to the plain 802.11 link type.
		for _, radius := range []int{0, 4, 8, 12, 20, 32, 36, 40} {
			if (linkType == linkTypeIEEE80211Capture) != (radius == 0) {
				continue
			}
			for _, mode := range []PrefilterMode{PrefilterAssessment, PrefilterManagement, PrefilterBeacon} {
				program, err := CompilePrefilter(linkType, PrefilterSpec{Mode: mode})
				if err != nil {
					t.Fatalf("compile mode %s for link type %d: %v", mode, linkType, err)
				}
				for _, tc := range cases {
					packet := tc.packet
					if radius > 0 {
						packet = wrapRadiotap(packet, radius)
					}
					want := tc.expected[mode]
					if got := runClassicBPF(t, program, packet); got != want {
						t.Errorf("link type %d, %d bytes of radiotap, mode %s, %s: kept=%t, want %t",
							linkType, radius, mode, tc.name, got, want)
					}
				}
			}
		}
	}
}

func TestPrefilterAddressRestriction(t *testing.T) {
	eapol := snap(0x888e)
	for _, linkType := range []uint32{linkTypeIEEE80211Capture, linkTypeRadiotapCapture} {
		program, err := CompilePrefilter(linkType, PrefilterSpec{Mode: PrefilterAssessment, Filter: testTarget})
		if err != nil {
			t.Fatalf("compile for link type %d: %v", linkType, err)
		}
		for _, radius := range []int{0, 8, 24} {
			if (linkType == linkTypeIEEE80211Capture) != (radius == 0) {
				continue
			}
			frame := func(t *testing.T) []byte {
				f := managementFrame(t, fcBeacon, testTarget)
				if radius > 0 {
					f = wrapRadiotap(f, radius)
				}
				return f
			}
			if !runClassicBPF(t, program, frame(t)) {
				t.Errorf("link type %d, %d radiotap bytes: expected the addressed beacon to be kept", linkType, radius)
			}
			unrelated := managementFrame(t, fcBeacon, "11:22:33:44:55:66")
			if radius > 0 {
				unrelated = wrapRadiotap(unrelated, radius)
			}
			if runClassicBPF(t, program, unrelated) {
				t.Errorf("link type %d, %d radiotap bytes: expected an unrelated beacon to be dropped", linkType, radius)
			}
			handshake := dataFrame(t, fcDataQoSFromDS, eapol)
			// Address the handshake to the requested address so the filter keeps it.
			copy(handshake[10:16], mustMACBytes(t, testTarget))
			if radius > 0 {
				handshake = wrapRadiotap(handshake, radius)
			}
			if !runClassicBPF(t, program, handshake) {
				t.Errorf("link type %d, %d radiotap bytes: expected the addressed EAPOL frame to be kept", linkType, radius)
			}
		}
	}
}

func TestPrefilterSpecEnabled(t *testing.T) {
	if (PrefilterSpec{}).Enabled() {
		t.Error("the zero spec must not install a filter")
	}
	if (PrefilterSpec{Mode: PrefilterAll}).Enabled() {
		t.Error("the all mode must not install a filter")
	}
	for _, mode := range []PrefilterMode{PrefilterAssessment, PrefilterManagement, PrefilterBeacon} {
		if !(PrefilterSpec{Mode: mode}).Enabled() {
			t.Errorf("mode %s must install a filter", mode)
		}
	}
	spec := PrefilterSpec{Mode: PrefilterAssessment}
	if _, err := spec.validate(); err != nil {
		t.Fatalf("validate without an address: %v", err)
	}
	if got, err := (PrefilterSpec{Mode: PrefilterAssessment, Filter: "de-ad-be-ef-00-01"}).validate(); err != nil || got != testTarget {
		t.Fatalf("dashed address normalization: got %q, %v", got, err)
	}
}

func TestPrefilterProgramsStayWithinKernelLimits(t *testing.T) {
	for _, linkType := range []uint32{linkTypeIEEE80211Capture, linkTypeRadiotapCapture} {
		for _, spec := range []PrefilterSpec{
			{Mode: PrefilterAssessment},
			{Mode: PrefilterAssessment, Filter: testTarget},
			{Mode: PrefilterManagement},
			{Mode: PrefilterManagement, Filter: testTarget},
			{Mode: PrefilterBeacon, Filter: testTarget},
		} {
			program, err := CompilePrefilter(linkType, spec)
			if err != nil {
				t.Fatalf("compile %+v: %v", spec, err)
			}
			if len(program) == 0 || len(program) > maxFilterInstructions {
				t.Fatalf("compile %+v produced %d instructions", spec, len(program))
			}
			if last := program[len(program)-1]; last.Code&0x07 != bpfRET {
				t.Fatalf("compile %+v does not end in a verdict", spec)
			}
		}
	}
}
