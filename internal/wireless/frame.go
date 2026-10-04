package wireless

import (
	"encoding/binary"
	"errors"
)

var (
	ErrFrameTooShort      = errors.New("802.11 frame is truncated")
	ErrUnsupportedVersion = errors.New("unsupported 802.11 protocol version")
)

// FrameType identifies the 802.11 frame category.
type FrameType uint8

const (
	FrameManagement FrameType = iota
	FrameControl
	FrameData
)

func (t FrameType) String() string {
	switch t {
	case FrameManagement:
		return "management"
	case FrameControl:
		return "control"
	case FrameData:
		return "data"
	default:
		return "unknown"
	}
}

// FrameInfo is a compact view of the 802.11 MAC header. Addresses remain
// binary so callers can avoid string conversion in packet-processing paths.
// An address is absent when its corresponding HasAddress field is false.
type FrameInfo struct {
	Type          FrameType
	Subtype       uint8
	ToDS          bool
	FromDS        bool
	Protected     bool
	Retry         bool
	MoreFragments bool
	Sequence      uint16
	Fragment      uint8
	HeaderLength  int
	Address1      [6]byte
	Address2      [6]byte
	Address3      [6]byte
	Address4      [6]byte
	HasAddress1   bool
	HasAddress2   bool
	HasAddress3   bool
	HasAddress4   bool
}

// ParseFrame parses the MAC header from one raw 802.11 frame. The input must
// start at the frame control field (radiotap and other capture link headers
// must be removed by the caller). It does not retain or copy the input bytes.
func ParseFrame(packet []byte) (FrameInfo, error) {
	var out FrameInfo
	if len(packet) < 2 {
		return out, ErrFrameTooShort
	}
	fc := binary.LittleEndian.Uint16(packet[:2])
	if fc&0x3 != 0 {
		return out, ErrUnsupportedVersion
	}
	out.Type = FrameType((fc >> 2) & 0x3)
	out.Subtype = uint8((fc >> 4) & 0xf)
	out.ToDS = fc&(1<<8) != 0
	out.FromDS = fc&(1<<9) != 0
	out.MoreFragments = fc&(1<<10) != 0
	out.Retry = fc&(1<<11) != 0
	out.Protected = fc&(1<<14) != 0

	switch out.Type {
	case FrameManagement:
		if len(packet) < 24 {
			return FrameInfo{}, ErrFrameTooShort
		}
		readAddr(&out.Address1, packet[4:10])
		readAddr(&out.Address2, packet[10:16])
		readAddr(&out.Address3, packet[16:22])
		out.HasAddress1, out.HasAddress2, out.HasAddress3 = true, true, true
		seq := binary.LittleEndian.Uint16(packet[22:24])
		out.Sequence, out.Fragment = seq>>4, uint8(seq&0xf)
		out.HeaderLength = 24
	case FrameControl:
		// CTS and ACK carry only receiver address; other control frames have
		// both receiver and transmitter addresses in their minimum header.
		need := 16
		if out.Subtype == 12 || out.Subtype == 13 {
			need = 10
		}
		if len(packet) < need {
			return FrameInfo{}, ErrFrameTooShort
		}
		readAddr(&out.Address1, packet[4:10])
		out.HasAddress1 = true
		if need == 16 {
			readAddr(&out.Address2, packet[10:16])
			out.HasAddress2 = true
		}
		out.HeaderLength = need
	case FrameData:
		if len(packet) < 24 {
			return FrameInfo{}, ErrFrameTooShort
		}
		readAddr(&out.Address1, packet[4:10])
		readAddr(&out.Address2, packet[10:16])
		readAddr(&out.Address3, packet[16:22])
		out.HasAddress1, out.HasAddress2, out.HasAddress3 = true, true, true
		seq := binary.LittleEndian.Uint16(packet[22:24])
		out.Sequence, out.Fragment = seq>>4, uint8(seq&0xf)
		out.HeaderLength = 24
		if out.ToDS && out.FromDS {
			if len(packet) < out.HeaderLength+6 {
				return FrameInfo{}, ErrFrameTooShort
			}
			readAddr(&out.Address4, packet[24:30])
			out.HasAddress4 = true
			out.HeaderLength += 6
		}
		// QoS data subtypes set bit 3. Ordered QoS frames also carry a
		// four-byte HT control field.
		if out.Subtype&8 != 0 {
			out.HeaderLength += 2
			if fc&(1<<15) != 0 {
				out.HeaderLength += 4
			}
			if len(packet) < out.HeaderLength {
				return FrameInfo{}, ErrFrameTooShort
			}
		}
	default:
		return FrameInfo{}, errors.New("reserved 802.11 frame type")
	}
	return out, nil
}

func readAddr(dst *[6]byte, src []byte) { copy(dst[:], src) }
