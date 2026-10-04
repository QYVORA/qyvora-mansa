// Package bluetooth implements ATT protocol encoding and decoding for GATT
// service discovery.
//
// The encoding side builds the requests a client sends and the decoding side
// interprets the responses a peer returns. Neither side performs I/O, so every
// rule below is checked directly by tests rather than inferred from a live
// adapter. A response that does not parse is reported as an error rather than
// partially applied.
package bluetooth

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// ATT opcodes used by service discovery. Only the request and response pairs
// that discovery needs are defined; anything else is rejected.
const (
	ATTErrorResponse           = 0x01
	ATTExchangeMTURequest      = 0x02
	ATTExchangeMTUResponse     = 0x03
	ATTFindInformationRequest  = 0x04
	ATTFindInformationResponse = 0x05
	ATTReadByTypeRequest       = 0x08
	ATTReadByTypeResponse      = 0x09
	ATTReadByGroupTypeRequest  = 0x10
	ATTReadByGroupTypeResponse = 0x11
)

// Attribute type UUIDs used to walk a GATT server.
const (
	// UUIDPrimaryService is the group type that lists services.
	UUIDPrimaryService = 0x2800
	// UUIDSecondaryService lists secondary services.
	UUIDSecondaryService = 0x2801
	// UUIDInclude marks a service included by another service.
	UUIDInclude = 0x2802
	// UUIDCharacteristicDeclaration is the type read to list characteristics.
	UUIDCharacteristicDeclaration = 0x2803
	// UUIDClientCharacteristicConfiguration is the descriptor most often used to
	// subscribe to notifications, so it is named explicitly.
	UUIDClientCharacteristicConfiguration = 0x2902
)

// Default ATT MTU when a peer does not negotiate one. The client may not assume
// a larger buffer than this without a completed exchange.
const DefaultATTMTU = 23

// maxATTResponseLength bounds a single decoded response so a peer cannot force
// an unbounded allocation.
const maxATTResponseLength = 512

// AttError is a decoded ATT error response.
type AttError struct {
	RequestOpcode uint8
	Handle        uint16
	ErrorCode     uint8
	// Message renders the standard error code with its Core Specification name.
	Message string
}

func (e *AttError) Error() string {
	return fmt.Sprintf("ATT error response: request 0x%02x at handle 0x%04x failed with 0x%02x (%s)",
		e.RequestOpcode, e.Handle, e.ErrorCode, e.Message)
}

// ErrorName returns the Core Specification name of an ATT error code.
func ErrorName(code uint8) string {
	names := map[uint8]string{
		0x01: "invalid handle",
		0x02: "read not permitted",
		0x03: "write not permitted",
		0x04: "invalid PDU",
		0x05: "insufficient authentication",
		0x06: "request not supported",
		0x07: "invalid offset",
		0x08: "insufficient authorization",
		0x09: "prepare queue full",
		0x0a: "attribute not found",
		0x0b: "attribute not long",
		0x0c: "encryption key size too short",
		0x0d: "invalid attribute value length",
		0x0e: "unlikely error",
		0x0f: "insufficient encryption",
		0x10: "unsupported group type",
		0x11: "insufficient resources",
		0x12: "database out of sync",
		0x13: "value not allowed",
	}
	if name, ok := names[code]; ok {
		return name
	}
	return "application-defined error"
}

// ParseErrorResponse decodes an ATT error response, or reports false when the
// PDU is not one.
func ParseErrorResponse(pdu []byte) (*AttError, bool, error) {
	if len(pdu) == 0 {
		return nil, false, errors.New("empty ATT PDU")
	}
	if pdu[0] != ATTErrorResponse {
		return nil, false, nil
	}
	if len(pdu) < 5 {
		return nil, true, fmt.Errorf("ATT error response of %d bytes is shorter than the 5-byte minimum", len(pdu))
	}
	attErr := &AttError{
		RequestOpcode: pdu[1],
		Handle:        binary.LittleEndian.Uint16(pdu[2:4]),
		ErrorCode:     pdu[4],
		Message:       ErrorName(pdu[4]),
	}
	return attErr, true, nil
}

// BuildExchangeMTURequest asks a peer to use at least the requested MTU. The
// value is the client's receive buffer size.
func BuildExchangeMTURequest(clientMTU uint16) ([]byte, error) {
	if clientMTU < DefaultATTMTU {
		return nil, fmt.Errorf("an ATT MTU of %d is below the %d-byte minimum", clientMTU, DefaultATTMTU)
	}
	pdu := make([]byte, 3)
	pdu[0] = ATTExchangeMTURequest
	binary.LittleEndian.PutUint16(pdu[1:3], clientMTU)
	return pdu, nil
}

// ParseExchangeMTUResponse returns the MTU a peer selected. A peer may return
// any value between 23 and its own limit, so the result is clamped to the
// minimum rather than trusted.
func ParseExchangeMTUResponse(pdu []byte) (uint16, error) {
	if len(pdu) == 0 {
		return 0, errors.New("empty ATT PDU")
	}
	if pdu[0] != ATTExchangeMTUResponse {
		return 0, fmt.Errorf("expected an MTU exchange response 0x%02x, got 0x%02x", ATTExchangeMTUResponse, pdu[0])
	}
	if len(pdu) < 3 {
		return 0, fmt.Errorf("MTU exchange response of %d bytes is shorter than 3 bytes", len(pdu))
	}
	mtu := binary.LittleEndian.Uint16(pdu[1:3])
	if mtu < DefaultATTMTU {
		return DefaultATTMTU, nil
	}
	return mtu, nil
}

// BuildFindInformationRequest asks a peer to describe the attributes in a
// handle range. This is the only discovery request a GATT client may send to an
// arbitrary range under the mandatory permissions.
func BuildFindInformationRequest(startHandle, endHandle uint16) ([]byte, error) {
	if err := checkHandleRange(startHandle, endHandle); err != nil {
		return nil, err
	}
	pdu := make([]byte, 5)
	pdu[0] = ATTFindInformationRequest
	binary.LittleEndian.PutUint16(pdu[1:3], startHandle)
	binary.LittleEndian.PutUint16(pdu[3:5], endHandle)
	return pdu, nil
}

// AttributeDescription is one entry of a find-information response.
type AttributeDescription struct {
	Handle uint16
	UUID   string
}

// baseUUIDSuffix completes a 16-bit UUID into the Bluetooth Base UUID, the
// range from which every 16-bit assigned number is drawn.
const baseUUIDSuffix = "-0000-1000-8000-00805F9B34FB"

// FormatUUID renders a 16-bit UUID in the canonical Bluetooth base form so a
// discovery result is directly comparable with published service definitions.
func FormatUUID(value uint16) string {
	return fmt.Sprintf("%04X%s", value, baseUUIDSuffix)
}

// ParseAttributeUUID decodes the UUID field of a find-information response,
// which is either two bytes for a 16-bit UUID or sixteen bytes for a 128-bit one.
func ParseAttributeUUID(field []byte) (string, error) {
	switch len(field) {
	case 2:
		return FormatUUID(binary.LittleEndian.Uint16(field)), nil
	case 16:
		var text strings.Builder
		const groups = 8
		// A 128-bit UUID is transmitted least-significant group first, so each
		// displayed group reverses the two bytes it was sent in.
		for i := 0; i < len(field); i += 2 {
			if i > 0 {
				text.WriteByte('-')
			}
			fmt.Fprintf(&text, "%02X%02X", field[i+1], field[i])
		}
		return strings.ToUpper(text.String()), nil
	default:
		return "", fmt.Errorf("a %d-byte attribute UUID is neither 16-bit nor 128-bit", len(field))
	}
}

// ParseFindInformationResponse decodes one find-information response. It returns
// the attributes it described, the handle a following request must start from,
// and whether the peer has more attributes to report.
//
// The caller must continue from nextStart until the peer signals the end, because
// a peer splits an attribute table across as many responses as its MTU allows.
func ParseFindInformationResponse(pdu []byte) (attributes []AttributeDescription, nextStart uint16, more bool, err error) {
	if len(pdu) == 0 {
		return nil, 0, false, errors.New("empty ATT PDU")
	}
	if pdu[0] != ATTFindInformationResponse {
		return nil, 0, false, fmt.Errorf("expected a find information response 0x%02x, got 0x%02x", ATTFindInformationResponse, pdu[0])
	}
	if len(pdu) < 2 {
		return nil, 0, false, errors.New("find information response is shorter than 2 bytes")
	}
	format := pdu[1]
	uuidLength := 0
	switch format {
	case 0x01:
		uuidLength = 2
	case 0x02:
		uuidLength = 16
	default:
		return nil, 0, false, fmt.Errorf("find information response format 0x%02x is not 16-bit or 128-bit", format)
	}
	entryLength := 2 + uuidLength
	body := pdu[2:]
	if len(body)%entryLength != 0 {
		return nil, 0, false, fmt.Errorf("find information response of %d bytes is not a whole number of %d-byte entries", len(body), entryLength)
	}
	var lastHandle uint16
	for offset := 0; offset < len(body); offset += entryLength {
		handle := binary.LittleEndian.Uint16(body[offset : offset+2])
		if offset > 0 && handle <= lastHandle {
			return nil, 0, false, fmt.Errorf("find information response returned handle 0x%04x after 0x%04x", handle, lastHandle)
		}
		uuid, uuidErr := ParseAttributeUUID(body[offset+2 : offset+entryLength])
		if uuidErr != nil {
			return nil, 0, false, uuidErr
		}
		attributes = append(attributes, AttributeDescription{Handle: handle, UUID: uuid})
		lastHandle = handle
	}
	if len(attributes) == 0 {
		return nil, 0, false, errors.New("find information response described no attributes")
	}
	return attributes, lastHandle + 1, true, nil
}

// BuildReadByGroupTypeRequest asks a peer to list the attributes of a type in a
// handle range. It is how a client enumerates services.
func BuildReadByGroupTypeRequest(startHandle, endHandle uint16, attributeType uint16) ([]byte, error) {
	if err := checkHandleRange(startHandle, endHandle); err != nil {
		return nil, err
	}
	// A request carries a 16-bit or a 128-bit UUID. The 16-bit form is always
	// valid because a 16-bit attribute type has a unique 128-bit expansion, so
	// the shorter encoding is used.
	pdu := make([]byte, 7)
	pdu[0] = ATTReadByGroupTypeRequest
	binary.LittleEndian.PutUint16(pdu[1:3], startHandle)
	binary.LittleEndian.PutUint16(pdu[3:5], endHandle)
	binary.LittleEndian.PutUint16(pdu[5:7], attributeType)
	return pdu, nil
}

// BuildReadByTypeRequest asks a peer to list the attributes of a type in a handle
// range. It is how a client enumerates characteristics and their descriptors.
func BuildReadByTypeRequest(startHandle, endHandle uint16, attributeType uint16) ([]byte, error) {
	if err := checkHandleRange(startHandle, endHandle); err != nil {
		return nil, err
	}
	pdu := make([]byte, 7)
	pdu[0] = ATTReadByTypeRequest
	binary.LittleEndian.PutUint16(pdu[1:3], startHandle)
	binary.LittleEndian.PutUint16(pdu[3:5], endHandle)
	binary.LittleEndian.PutUint16(pdu[5:7], attributeType)
	return pdu, nil
}

// ServiceEntry is one service from a read-by-group-type response.
type ServiceEntry struct {
	DeclarationHandle uint16
	EndGroupHandle    uint16
	UUID              string
}

// ParseServiceResponse decodes one read-by-group-type response for a service
// type. The error response 0x0a (attribute not found) means discovery is
// complete, which is reported as complete rather than as a failure.
func ParseServiceResponse(pdu []byte) (entries []ServiceEntry, nextStart uint16, done bool, err error) {
	if attErr, isError, parseErr := ParseErrorResponse(pdu); isError {
		if parseErr != nil {
			return nil, 0, false, parseErr
		}
		if attErr.ErrorCode == 0x0a {
			return nil, 0, true, nil
		}
		return nil, 0, false, attErr
	}
	if len(pdu) == 0 {
		return nil, 0, false, errors.New("empty ATT PDU")
	}
	if pdu[0] != ATTReadByGroupTypeResponse {
		return nil, 0, false, fmt.Errorf("expected a read by group type response 0x%02x, got 0x%02x", ATTReadByGroupTypeResponse, pdu[0])
	}
	if len(pdu) < 2 {
		return nil, 0, false, errors.New("read by group type response is shorter than 2 bytes")
	}
	entryLength := int(pdu[1])
	if entryLength < 6 {
		return nil, 0, false, fmt.Errorf("read by group type entry length %d is below the 6-byte minimum", entryLength)
	}
	body := pdu[2:]
	if len(body)%entryLength != 0 {
		return nil, 0, false, fmt.Errorf("read by group type response of %d bytes is not a whole number of %d-byte entries", len(body), entryLength)
	}
	var lastEnd uint16
	for offset := 0; offset < len(body); offset += entryLength {
		declaration := binary.LittleEndian.Uint16(body[offset : offset+2])
		end := binary.LittleEndian.Uint16(body[offset+2 : offset+4])
		if end < declaration {
			return nil, 0, false, fmt.Errorf("service at handle 0x%04x ends at 0x%04x before it starts", declaration, end)
		}
		if offset > 0 && declaration <= lastEnd {
			return nil, 0, false, fmt.Errorf("read by group type response returned handle 0x%04x after group ending 0x%04x", declaration, lastEnd)
		}
		uuid, uuidErr := ParseAttributeUUID(body[offset+4 : offset+entryLength])
		if uuidErr != nil {
			return nil, 0, false, uuidErr
		}
		entries = append(entries, ServiceEntry{DeclarationHandle: declaration, EndGroupHandle: end, UUID: uuid})
		lastEnd = end
	}
	if len(entries) == 0 {
		return nil, 0, false, errors.New("read by group type response described no entries")
	}
	return entries, lastEnd + 1, false, nil
}

// CharacteristicEntry is one characteristic from a read-by-type response. The
// value field holds the declaration: properties, the value handle, and the UUID.
type CharacteristicEntry struct {
	DeclarationHandle uint16
	Properties        uint8
	ValueHandle       uint16
	UUID              string
}

// ParseCharacteristicResponse decodes one read-by-type response for the
// characteristic declaration type. The attribute not found error means discovery
// is complete for the range.
func ParseCharacteristicResponse(pdu []byte) (entries []CharacteristicEntry, nextStart uint16, done bool, err error) {
	if attErr, isError, parseErr := ParseErrorResponse(pdu); isError {
		if parseErr != nil {
			return nil, 0, false, parseErr
		}
		if attErr.ErrorCode == 0x0a {
			return nil, 0, true, nil
		}
		return nil, 0, false, attErr
	}
	if len(pdu) == 0 {
		return nil, 0, false, errors.New("empty ATT PDU")
	}
	if pdu[0] != ATTReadByTypeResponse {
		return nil, 0, false, fmt.Errorf("expected a read by type response 0x%02x, got 0x%02x", ATTReadByTypeResponse, pdu[0])
	}
	if len(pdu) < 2 {
		return nil, 0, false, errors.New("read by type response is shorter than 2 bytes")
	}
	entryLength := int(pdu[1])
	// Declaration handles plus properties, a value handle, and a UUID of at
	// least 16 bits.
	if entryLength < 7 {
		return nil, 0, false, fmt.Errorf("read by type entry length %d is below the 7-byte minimum", entryLength)
	}
	body := pdu[2:]
	if len(body)%entryLength != 0 {
		return nil, 0, false, fmt.Errorf("read by type response of %d bytes is not a whole number of %d-byte entries", len(body), entryLength)
	}
	var lastHandle uint16
	for offset := 0; offset < len(body); offset += entryLength {
		declaration := binary.LittleEndian.Uint16(body[offset : offset+2])
		if offset > 0 && declaration <= lastHandle {
			return nil, 0, false, fmt.Errorf("read by type response returned handle 0x%04x after 0x%04x", declaration, lastHandle)
		}
		properties := body[offset+2]
		valueHandle := binary.LittleEndian.Uint16(body[offset+3 : offset+5])
		if valueHandle <= declaration {
			return nil, 0, false, fmt.Errorf("characteristic at handle 0x%04x has value handle 0x%04x, which is not above it", declaration, valueHandle)
		}
		uuid, uuidErr := ParseAttributeUUID(body[offset+5 : offset+entryLength])
		if uuidErr != nil {
			return nil, 0, false, uuidErr
		}
		entries = append(entries, CharacteristicEntry{
			DeclarationHandle: declaration, Properties: properties, ValueHandle: valueHandle, UUID: uuid,
		})
		lastHandle = declaration
	}
	if len(entries) == 0 {
		return nil, 0, false, errors.New("read by type response described no entries")
	}
	return entries, lastHandle + 2, false, nil
}

// checkHandleRange rejects a range a GATT client must not send.
func checkHandleRange(startHandle, endHandle uint16) error {
	if startHandle == 0 {
		return errors.New("handle 0x0000 is not a valid attribute handle")
	}
	if endHandle < startHandle {
		return fmt.Errorf("handle range 0x%04x-0x%04x ends before it starts", startHandle, endHandle)
	}
	if endHandle == 0xffff {
		return errors.New("0xffff is not an attribute handle and cannot be a range end")
	}
	return nil
}

// ATTMaxHandle is the highest handle a client may request, used when a peer has
// not declared a smaller table.
const ATTMaxHandle = 0xffff - 1
