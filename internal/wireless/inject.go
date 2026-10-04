package wireless

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Management frame subtypes used by Mansa operations. Values are the 802.11
// subtype numbers, not bit patterns.
const (
	SubtypeAuthentication   uint8 = 0
	SubtypeProbeRequest     uint8 = 4
	SubtypeProbeResponse    uint8 = 5
	SubtypeBeacon           uint8 = 8
	SubtypeDisassociation   uint8 = 10
	SubtypeDeauthentication uint8 = 12
	SubtypeAssociation      uint8 = 1
)

// Reason codes carried by disassociation and deauthentication frames.
const (
	ReasonUnspecified     uint16 = 1
	ReasonAuthExpired     uint16 = 7
	ReasonDeauthenticated uint16 = 3
)

// Authentication algorithms used in authentication frames.
const (
	AuthAlgorithmOpen uint16 = 0
	AuthAlgorithmSKC  uint16 = 1
	AuthAlgorithmRSN  uint16 = 2
)

var (
	ErrEmptyAddress = errors.New("802.11 address is all zero")
	ErrFrameTooLong = errors.New("802.11 frame exceeds the transmission limit")
)

// maxFrameLen bounds a constructed frame. A management frame with a full
// information element list cannot approach this.
const maxFrameLen = 2312

// MACAddress is a 48-bit 802.11 address.
type MACAddress [6]byte

// String renders the address in canonical lowercase colon-separated form.
func (a MACAddress) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", a[0], a[1], a[2], a[3], a[4], a[5])
}

// BroadcastAddress is the all-ones address.
var BroadcastAddress = MACAddress{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// IsBroadcast reports whether the address is the all-ones address.
func (a MACAddress) IsBroadcast() bool { return a == BroadcastAddress }

// IsZero reports whether the address is all zeros, which 802.11 uses to mean
// "unspecified" in several address fields.
func (a MACAddress) IsZero() bool { return a == MACAddress{} }

// ParseMACAddress parses the canonical colon or dash separated 802.11 form.
// It accepts exactly six octets and rejects a broadcast or zero address,
// because neither is a valid source for a frame Mansa transmits.
func ParseMACAddress(value string) (MACAddress, error) {
	var out MACAddress
	if len(value) != 17 {
		return out, fmt.Errorf("invalid 802.11 address %q: expected 17 characters", value)
	}
	seen := 0
	for i := 0; i < len(value); i += 3 {
		if i > 0 {
			// The separator sits immediately before the octet that starts at i.
			if value[i-1] != ':' && value[i-1] != '-' {
				return out, fmt.Errorf("invalid 802.11 address %q: separator at offset %d", value, i-1)
			}
		}
		hi, hiOK := hexNibble(value[i])
		lo, loOK := hexNibble(value[i+1])
		if !hiOK || !loOK {
			return out, fmt.Errorf("invalid 802.11 address %q: non-hexadecimal digit at offset %d", value, i)
		}
		out[seen] = hi<<4 | lo
		seen++
	}
	if out.IsZero() {
		return out, fmt.Errorf("invalid 802.11 address %q: address is all zero", value)
	}
	if out.IsBroadcast() {
		return out, fmt.Errorf("invalid 802.11 address %q: broadcast cannot be used as a source address", value)
	}
	return out, nil
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// RadiotapHeader returns an eight byte radiotap header that declares no
// optional fields. Drivers on a radiotap interface require the header, and an
// empty field list keeps the frame identical to the one a capture would show.
func RadiotapHeader() []byte {
	header := make([]byte, 8)
	header[0] = 0 // radiotap version
	header[1] = 0 // padding
	binary.LittleEndian.PutUint16(header[2:4], 8)
	binary.LittleEndian.PutUint32(header[4:8], 0) // present bitmap: no fields
	return header
}

// BuildManagementFrame builds a management frame with the given subtype and
// three address fields. The receiver address is address 1, the transmitter is
// address 2, and address 3 is the BSSID for association-like management frames.
// The result starts at the frame control field; a radiotap header must be
// prepended when the destination interface expects one.
func BuildManagementFrame(subtype uint8, receiver, transmitter, bssid MACAddress, sequence uint16, body []byte) ([]byte, error) {
	frame := make([]byte, 24, 24+len(body))
	if len(body) > maxFrameLen-24 {
		return nil, ErrFrameTooLong
	}
	frameControl := uint16(FrameManagement)<<2 | uint16(subtype&0xf)<<4
	binary.LittleEndian.PutUint16(frame[0:2], frameControl)
	binary.LittleEndian.PutUint16(frame[2:4], 0) // duration
	copy(frame[4:10], receiver[:])
	copy(frame[10:16], transmitter[:])
	copy(frame[16:22], bssid[:])
	binary.LittleEndian.PutUint16(frame[22:24], sequence<<4)
	return append(frame, body...), nil
}

// BuildProbeRequest builds a probe request for one SSID. An SSID longer than
// the 802.11 limit is rejected rather than truncated, because a silently
// shortened SSID would probe for a different network than requested.
func BuildProbeRequest(source MACAddress, ssid []byte, sequence uint16) ([]byte, error) {
	if len(ssid) > 32 {
		return nil, fmt.Errorf("probe request SSID is %d bytes, above the 32 byte limit", len(ssid))
	}
	body := make([]byte, 0, 2+len(ssid))
	body = append(body, 0, byte(len(ssid)))
	body = append(body, ssid...)
	return BuildManagementFrame(SubtypeProbeRequest, BroadcastAddress, source, BroadcastAddress, sequence, body)
}

// BuildAuthentication builds an authentication frame carrying one algorithm
// and status code.
func BuildAuthentication(source, bssid MACAddress, algorithm, status uint16, sequence uint16) ([]byte, error) {
	body := make([]byte, 6)
	binary.LittleEndian.PutUint16(body[0:2], algorithm)
	binary.LittleEndian.PutUint16(body[2:4], status)
	binary.LittleEndian.PutUint16(body[4:6], sequence)
	return BuildManagementFrame(SubtypeAuthentication, bssid, source, bssid, sequence, body)
}

// BuildDisassociation builds a disassociation or deauthentication frame. The
// receiver must be a single station: a broadcast receiver is refused, because
// every module that sends these frames is scoped to one authorized target and a
// broadcast frame would silently exceed that scope.
func BuildDisassociation(subtype uint8, receiver, source, bssid MACAddress, reason uint16, sequence uint16) ([]byte, error) {
	if receiver.IsBroadcast() {
		return nil, errors.New("refusing to build a broadcast disassociation or deauthentication frame")
	}
	body := make([]byte, 2)
	binary.LittleEndian.PutUint16(body[0:2], reason)
	return BuildManagementFrame(subtype, receiver, source, bssid, sequence, body)
}

// BuildBeacon builds a beacon frame advertising one SSID with a fixed
// capability set. The capability set is reported verbatim in the frame body so
// a receiver of the frame sees the same configuration a capture would show.
func BuildBeacon(source MACAddress, ssid string, capability uint16, sequence uint16) ([]byte, error) {
	raw := []byte(ssid)
	if len(raw) > 32 {
		return nil, fmt.Errorf("beacon SSID is %d bytes, above the 32 byte limit", len(raw))
	}
	body := make([]byte, 0, 12+2+len(raw))
	timestamp := make([]byte, 8) // zeroed: the local clock is not an observation
	body = append(body, timestamp...)
	body = binary.LittleEndian.AppendUint16(body, 100) // beacon interval in time units
	body = binary.LittleEndian.AppendUint16(body, capability)
	body = append(body, 0, byte(len(raw)))
	body = append(body, raw...)
	return BuildManagementFrame(SubtypeBeacon, BroadcastAddress, source, source, sequence, body)
}

// SequenceNumber advances a 12-bit sequence counter the way 802.11 does.
func SequenceNumber(sequence uint16) uint16 { return (sequence + 1) & 0x0fff }
