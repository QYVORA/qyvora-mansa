package wireless

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	ErrMalformedInformationElement = errors.New("malformed 802.11 information element")
	ErrMalformedRSN                = errors.New("malformed RSN information element")
)

// ManagementElements contains selected values decoded from beacon or probe
// response information elements. SSID is a Go string so arbitrary SSID bytes
// are preserved; callers should escape it when rendering terminal output.
type ManagementElements struct {
	SSID            string
	SSIDPresent     bool
	Privacy         bool
	WPA             bool
	WPS             bool
	Channel         uint8
	Band            string
	SupportedRates  []uint8
	CapabilityFlags []string
	RSN             *RSNInformation
}

// RSNInformation contains the security fields needed for passive assessment.
type RSNInformation struct {
	GroupCipher     string
	PairwiseCiphers []string
	AKMSuites       []string
	PMFCapable      bool
	PMFRequired     bool
}

// ParseBeaconProbeResponse decodes the fixed body and information elements of
// an 802.11 beacon or probe response frame. Other frame types/subtypes fail.
func ParseBeaconProbeResponse(packet []byte) (ManagementElements, error) {
	var out ManagementElements
	frame, err := ParseFrame(packet)
	if err != nil {
		return out, err
	}
	if frame.Type != FrameManagement || (frame.Subtype != 5 && frame.Subtype != 8) {
		return out, errors.New("frame is not a beacon or probe response")
	}
	// Both frame subtypes carry an eight-byte timestamp, beacon interval, and
	// capability field before the information-element list.
	const fixedBodyLength = 12
	if len(packet) < frame.HeaderLength+fixedBodyLength {
		return out, ErrFrameTooShort
	}
	out, err = ParseInformationElements(packet[frame.HeaderLength+fixedBodyLength:])
	if err != nil {
		return ManagementElements{}, err
	}
	capabilities := binary.LittleEndian.Uint16(packet[frame.HeaderLength+10 : frame.HeaderLength+12])
	out.Privacy = capabilities&(1<<4) != 0
	out.CapabilityFlags = parseCapabilityFlags(capabilities)
	return out, nil
}

func parseCapabilityFlags(bits uint16) []string {
	flags := [...]struct {
		bit  uint16
		name string
	}{
		{1 << 0, "ESS"}, {1 << 1, "IBSS"}, {1 << 2, "CF-Pollable"},
		{1 << 3, "CF-Poll-Request"}, {1 << 4, "Privacy"}, {1 << 5, "Short-Preamble"},
		{1 << 6, "PBCC"}, {1 << 7, "Channel-Agility"}, {1 << 8, "Spectrum-Management"},
		{1 << 9, "QoS"}, {1 << 10, "Short-Slot-Time"}, {1 << 11, "APSD"},
		{1 << 12, "Radio-Measurement"}, {1 << 13, "DSSS-OFDM"},
		{1 << 14, "Delayed-Block-ACK"}, {1 << 15, "Immediate-Block-ACK"},
	}
	out := make([]string, 0, len(flags))
	for _, flag := range flags {
		if bits&flag.bit != 0 {
			out = append(out, flag.name)
		}
	}
	return out
}

// ParseInformationElements parses a bounded 802.11 element-ID/length/value
// stream. Unknown elements are skipped. Repeated known elements use their
// first value, which keeps malformed or unusual streams deterministic.
func ParseInformationElements(data []byte) (ManagementElements, error) {
	var out ManagementElements
	for offset := 0; offset < len(data); {
		if len(data)-offset < 2 {
			return ManagementElements{}, fmt.Errorf("%w at byte %d: missing element header", ErrMalformedInformationElement, offset)
		}
		id, length := data[offset], int(data[offset+1])
		offset += 2
		if length > len(data)-offset {
			return ManagementElements{}, fmt.Errorf("%w at byte %d: declared length %d exceeds remaining %d", ErrMalformedInformationElement, offset-2, length, len(data)-offset)
		}
		value := data[offset : offset+length]
		offset += length

		switch id {
		case 0: // SSID
			if !out.SSIDPresent {
				if length > 32 {
					return ManagementElements{}, fmt.Errorf("%w: SSID length %d exceeds 32 bytes", ErrMalformedInformationElement, length)
				}
				out.SSID, out.SSIDPresent = string(value), true
			}
		case 1, 50: // Supported / extended supported rates
			if len(out.SupportedRates)+length <= 256 {
				out.SupportedRates = append(out.SupportedRates, value...)
			}
		case 3: // DS parameter set
			if out.Channel == 0 && length >= 1 {
				out.Channel = value[0]
				if value[0] <= 14 {
					out.Band = "2.4GHz"
				}
			}
		case 61: // HT Operation: primary channel
			if out.Channel == 0 && length >= 1 {
				out.Channel = value[0]
				if value[0] > 14 {
					out.Band = "5GHz"
				} else if value[0] != 0 {
					out.Band = "2.4GHz"
				}
			}
		case 48: // RSN
			if out.RSN == nil {
				rsn, err := parseRSN(value)
				if err != nil {
					return ManagementElements{}, err
				}
				out.RSN = &rsn
			}
		case 221: // WPA vendor-specific IE (OUI 00:50:F2, type 1)
			if len(value) >= 4 && value[0] == 0x00 && value[1] == 0x50 && value[2] == 0xf2 && value[3] == 1 {
				out.WPA = true
			} else if len(value) >= 4 && value[0] == 0x00 && value[1] == 0x50 && value[2] == 0xf2 && value[3] == 4 {
				// Wi-Fi Protected Setup uses the same Microsoft OUI as WPA,
				// with vendor type 4. Presence is an advertisement only; it
				// does not establish that WPS is enabled for enrollment.
				out.WPS = true
			}
		case 255: // Extension element, including HE Operation.
			if length > 0 && value[0] == 36 { // HE Operation extension ID
				channel, is6GHz, err := parseHEOperation(value[1:])
				if err != nil {
					return ManagementElements{}, err
				}
				if is6GHz {
					out.Channel, out.Band = channel, "6GHz"
				}
			}
		}
	}
	return out, nil
}

func parseHEOperation(data []byte) (channel uint8, is6GHz bool, err error) {
	// HE Operation fixed fields are params (4), BSS color (1), and basic
	// MCS/NSS (2). Optional fields are signaled in params.
	if len(data) < 7 {
		return 0, false, ErrMalformedInformationElement
	}
	params := binary.LittleEndian.Uint32(data[:4])
	const (
		heOperationVHTInfo     = uint32(1 << 14)
		heOperationCohostedBSS = uint32(1 << 15)
		heOperation6GHzInfo    = uint32(1 << 17)
	)
	if params&heOperation6GHzInfo == 0 {
		return 0, false, nil
	}
	offset := 7
	if params&heOperationVHTInfo != 0 {
		offset += 3
	}
	if params&heOperationCohostedBSS != 0 {
		offset++
	}
	const sixGHzOperationLength = 5
	if len(data)-offset < sixGHzOperationLength {
		return 0, false, ErrMalformedInformationElement
	}
	channel = data[offset]
	if channel == 0 || channel > 233 {
		return 0, false, ErrMalformedInformationElement
	}
	return channel, true, nil
}

func parseRSN(data []byte) (RSNInformation, error) {
	var out RSNInformation
	malformed := func() (RSNInformation, error) { return RSNInformation{}, ErrMalformedRSN }
	if len(data) < 2 || binary.LittleEndian.Uint16(data[:2]) != 1 {
		return malformed()
	}
	offset := 2
	readSuite := func(akm bool) (string, bool) {
		if len(data)-offset < 4 {
			return "", false
		}
		v := data[offset : offset+4]
		offset += 4
		return suiteName(v[0], v[1], v[2], v[3], akm), true
	}
	if out.GroupCipher, _ = readSuite(false); out.GroupCipher == "" {
		return malformed()
	}
	pairwiseCount, ok := readCount(data, &offset)
	if !ok || int(pairwiseCount) > (len(data)-offset)/4 {
		return malformed()
	}
	for i := 0; i < int(pairwiseCount); i++ {
		name, ok := readSuite(false)
		if !ok {
			return malformed()
		}
		out.PairwiseCiphers = append(out.PairwiseCiphers, name)
	}
	akmCount, ok := readCount(data, &offset)
	if !ok || int(akmCount) > (len(data)-offset)/4 {
		return malformed()
	}
	for i := 0; i < int(akmCount); i++ {
		name, ok := readSuite(true)
		if !ok {
			return malformed()
		}
		out.AKMSuites = append(out.AKMSuites, name)
	}
	if len(data)-offset >= 2 {
		capabilities := binary.LittleEndian.Uint16(data[offset : offset+2])
		out.PMFCapable = capabilities&(1<<7) != 0
		out.PMFRequired = capabilities&(1<<6) != 0
		offset += 2
	} else if offset != len(data) {
		return malformed()
	}
	// Optional PMKID list followed by an optional group management cipher.
	if offset < len(data) {
		pmkidCount, ok := readCount(data, &offset)
		if !ok || int(pmkidCount) > (len(data)-offset)/16 {
			return malformed()
		}
		offset += int(pmkidCount) * 16
	}
	if offset < len(data) {
		if _, ok := readSuite(false); !ok {
			return malformed()
		}
	}
	if offset != len(data) {
		return malformed()
	}
	return out, nil
}

func readCount(data []byte, offset *int) (uint16, bool) {
	if len(data)-*offset < 2 {
		return 0, false
	}
	count := binary.LittleEndian.Uint16(data[*offset : *offset+2])
	*offset += 2
	return count, true
}

func suiteName(a, b, c, suite byte, akm bool) string {
	if a != 0x00 || b != 0x0f || c != 0xac {
		return "unknown"
	}
	if akm {
		switch suite {
		case 1:
			return "802.1X"
		case 2:
			return "PSK"
		case 3:
			return "FT-802.1X"
		case 4:
			return "FT-PSK"
		case 5:
			return "802.1X-SHA256"
		case 6:
			return "PSK-SHA256"
		case 8:
			return "SAE"
		case 9:
			return "FT-SAE"
		case 18:
			return "OWE"
		default:
			return "unknown"
		}
	}
	switch suite {
	case 1:
		return "WEP-40"
	case 2:
		return "TKIP"
	case 4:
		return "CCMP-128"
	case 5:
		return "WEP-104"
	case 8:
		return "GCMP-128"
	case 9:
		return "GCMP-256"
	case 10:
		return "CCMP-256"
	default:
		return "unknown"
	}
}
