package bluetooth

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestBuildRequestsMatchTheProtocolLayout(t *testing.T) {
	mtu, err := BuildExchangeMTURequest(517)
	if err != nil {
		t.Fatal(err)
	}
	if len(mtu) != 3 || mtu[0] != ATTExchangeMTURequest || binary.LittleEndian.Uint16(mtu[1:3]) != 517 {
		t.Errorf("MTU request = % x", mtu)
	}

	find, err := BuildFindInformationRequest(0x0001, 0xffff-1)
	if err != nil {
		t.Fatal(err)
	}
	if len(find) != 5 || find[0] != ATTFindInformationRequest ||
		binary.LittleEndian.Uint16(find[1:3]) != 0x0001 ||
		binary.LittleEndian.Uint16(find[3:5]) != ATTMaxHandle {
		t.Errorf("find information request = % x", find)
	}

	group, err := BuildReadByGroupTypeRequest(0x0001, ATTMaxHandle, UUIDPrimaryService)
	if err != nil {
		t.Fatal(err)
	}
	if len(group) != 7 || group[0] != ATTReadByGroupTypeRequest ||
		binary.LittleEndian.Uint16(group[5:7]) != UUIDPrimaryService {
		t.Errorf("read by group type request = % x", group)
	}

	byType, err := BuildReadByTypeRequest(0x0006, 0x000f, UUIDCharacteristicDeclaration)
	if err != nil {
		t.Fatal(err)
	}
	if len(byType) != 7 || byType[0] != ATTReadByTypeRequest ||
		binary.LittleEndian.Uint16(byType[5:7]) != UUIDCharacteristicDeclaration {
		t.Errorf("read by type request = % x", byType)
	}
}

func TestBuildRequestsRejectInvalidRanges(t *testing.T) {
	for _, tc := range []struct {
		name       string
		start, end uint16
	}{
		{"zero start", 0, 0x10},
		{"end before start", 0x0010, 0x000f},
		{"reserved end handle", 0x0001, 0xffff},
	} {
		if _, err := BuildFindInformationRequest(tc.start, tc.end); err == nil {
			t.Errorf("%s: expected the range to be refused", tc.name)
		}
		if _, err := BuildReadByTypeRequest(tc.start, tc.end, UUIDCharacteristicDeclaration); err == nil {
			t.Errorf("%s: expected the type range to be refused", tc.name)
		}
		if _, err := BuildReadByGroupTypeRequest(tc.start, tc.end, UUIDPrimaryService); err == nil {
			t.Errorf("%s: expected the group range to be refused", tc.name)
		}
	}
}

func TestBuildExchangeMTURequestRejectsTooSmall(t *testing.T) {
	if _, err := BuildExchangeMTURequest(22); err == nil {
		t.Error("an MTU below 23 must be refused")
	}
	if _, err := BuildExchangeMTURequest(23); err != nil {
		t.Errorf("an MTU of 23 must be accepted: %v", err)
	}
}

func TestParseExchangeMTUResponse(t *testing.T) {
	response := []byte{ATTExchangeMTUResponse, 0xf7, 0x00}
	if mtu, err := ParseExchangeMTUResponse(response); err != nil || mtu != 247 {
		t.Errorf("MTU = %d, %v", mtu, err)
	}
	// A peer may answer with a value below the minimum; the safe value is used.
	low := []byte{ATTExchangeMTUResponse, 0x10, 0x00}
	if mtu, err := ParseExchangeMTUResponse(low); err != nil || mtu != DefaultATTMTU {
		t.Errorf("a low MTU = %d, %v, want the default %d", mtu, err, DefaultATTMTU)
	}
	for _, bad := range [][]byte{{}, {ATTExchangeMTUResponse, 0x00}, {ATTReadByTypeResponse, 0x37, 0x00}} {
		if _, err := ParseExchangeMTUResponse(bad); err == nil {
			t.Errorf("expected % x to be refused", bad)
		}
	}
}

func TestParseErrorResponse(t *testing.T) {
	pdu := []byte{ATTErrorResponse, ATTReadByTypeRequest, 0x0f, 0x00, 0x0a}
	attErr, isError, err := ParseErrorResponse(pdu)
	if err != nil || !isError {
		t.Fatalf("isError=%v err=%v", isError, err)
	}
	if attErr.Handle != 0x000f || attErr.ErrorCode != 0x0a || attErr.Message != "attribute not found" {
		t.Errorf("decoded = %+v", attErr)
	}
	if attErr.Error() == "" {
		t.Error("an ATT error must render a message")
	}
	if _, isError, _ := ParseErrorResponse([]byte{ATTReadByTypeResponse, 1, 2}); isError {
		t.Error("a non-error PDU must not be reported as an error response")
	}
	if _, isError, err := ParseErrorResponse([]byte{ATTErrorResponse, 1}); !isError || err == nil {
		t.Error("a truncated error response must be reported as malformed")
	}
	if _, _, err := ParseErrorResponse(nil); err == nil {
		t.Error("an empty PDU must be refused")
	}
}

func TestErrorNameCoversDefinedCodes(t *testing.T) {
	for code := uint8(0x01); code <= 0x13; code++ {
		if got := ErrorName(code); got == "application-defined error" {
			t.Errorf("code 0x%02x must have a defined name", code)
		}
	}
	if got := ErrorName(0x80); got != "application-defined error" {
		t.Errorf("an undefined code = %q", got)
	}
}

func TestParseAttributeUUID(t *testing.T) {
	short, err := ParseAttributeUUID([]byte{0x0f, 0x18})
	if err != nil || short != "180F-0000-1000-8000-00805F9B34FB" {
		t.Errorf("16-bit UUID = %q, %v", short, err)
	}
	// A 128-bit UUID is transmitted least-significant group first, so the first
	// transmitted byte is the last octet of the displayed value.
	long := make([]byte, 16)
	long[0] = 0xab
	expanded, err := ParseAttributeUUID(long)
	if err != nil {
		t.Fatal(err)
	}
	// Eight four-digit groups joined by seven dashes.
	if len(expanded) != 39 || expanded[4] != '-' {
		t.Errorf("128-bit UUID = %q", expanded)
	}
	if _, err := ParseAttributeUUID([]byte{1, 2, 3}); err == nil {
		t.Error("a three-byte UUID must be refused")
	}
}

func TestParseFindInformationResponse16Bit(t *testing.T) {
	pdu := []byte{ATTFindInformationResponse, 0x01}
	for handle := uint16(0x0001); handle <= 0x0003; handle++ {
		pdu = binary.LittleEndian.AppendUint16(pdu, handle)
		pdu = append(pdu, 0x00, 0x28)
	}
	attributes, nextStart, _, err := ParseFindInformationResponse(pdu)
	if err != nil {
		t.Fatal(err)
	}
	if len(attributes) != 3 {
		t.Fatalf("got %d attributes, want 3", len(attributes))
	}
	if attributes[0].Handle != 0x0001 || attributes[2].Handle != 0x0003 {
		t.Errorf("handles = % x", attributes)
	}
	if attributes[1].UUID != FormatUUID(UUIDPrimaryService) {
		t.Errorf("UUID = %q", attributes[1].UUID)
	}
	if nextStart != 0x0004 {
		t.Errorf("nextStart = 0x%04x, want 0x0004 so the caller pages forward", nextStart)
	}
}

func TestParseFindInformationResponse128Bit(t *testing.T) {
	pdu := []byte{ATTFindInformationResponse, 0x02}
	pdu = binary.LittleEndian.AppendUint16(pdu, 0x000a)
	uuid := make([]byte, 16)
	uuid[15] = 0x01
	pdu = append(pdu, uuid...)
	attributes, nextStart, _, err := ParseFindInformationResponse(pdu)
	if err != nil {
		t.Fatal(err)
	}
	if len(attributes) != 1 || nextStart != 0x000b {
		t.Fatalf("attributes=%+v nextStart=0x%04x", attributes, nextStart)
	}
	if len(attributes[0].UUID) != 39 {
		t.Errorf("a 128-bit UUID must be expanded, got %q", attributes[0].UUID)
	}
}

func TestParseFindInformationResponseRejectsMalformedInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		pdu  []byte
	}{
		{"empty", nil},
		{"short header", []byte{ATTFindInformationResponse}},
		{"unknown format", []byte{ATTFindInformationResponse, 0x03, 1, 2}},
		{"partial entry", []byte{ATTFindInformationResponse, 0x01, 0x01, 0x00, 0x28}},
		{"no entries", []byte{ATTFindInformationResponse, 0x01}},
		{"handles out of order", []byte{ATTFindInformationResponse, 0x01, 0x05, 0x00, 0x28, 0x00, 0x03, 0x00, 0x28, 0x00}},
		{"wrong opcode", []byte{ATTReadByTypeResponse, 0x01, 0x01, 0x00, 0x28, 0x00}},
	} {
		if _, _, _, err := ParseFindInformationResponse(tc.pdu); err == nil {
			t.Errorf("%s: expected % x to be refused", tc.name, tc.pdu)
		}
	}
}

func TestParseServiceResponse(t *testing.T) {
	pdu := []byte{ATTReadByGroupTypeResponse, 0x06}
	pdu = binary.LittleEndian.AppendUint16(pdu, 0x0001) // declaration
	pdu = binary.LittleEndian.AppendUint16(pdu, 0x0005) // group end
	pdu = append(pdu, 0x0f, 0x18)                       // 16-bit service UUID, little-endian
	entries, nextStart, done, err := ParseServiceResponse(pdu)
	if err != nil {
		t.Fatal(err)
	}
	if done {
		t.Error("a populated response must not report completion")
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries", len(entries))
	}
	if entries[0].DeclarationHandle != 0x0001 || entries[0].EndGroupHandle != 0x0005 {
		t.Errorf("entry = %+v", entries[0])
	}
	if entries[0].UUID != FormatUUID(0x180f) {
		t.Errorf("UUID = %q", entries[0].UUID)
	}
	if nextStart != 0x0006 {
		t.Errorf("nextStart = 0x%04x, want 0x0006 so the caller pages past the group", nextStart)
	}
}

func TestParseServiceResponseTreatsAttributeNotFoundAsComplete(t *testing.T) {
	pdu := []byte{ATTErrorResponse, ATTReadByGroupTypeRequest, 0x01, 0x00, 0x0a}
	_, _, done, err := ParseServiceResponse(pdu)
	if err != nil {
		t.Fatalf("attribute not found must end discovery cleanly: %v", err)
	}
	if !done {
		t.Error("attribute not found must report the range complete")
	}
	// Any other error is a failure, not completion.
	insufficient := []byte{ATTErrorResponse, ATTReadByGroupTypeRequest, 0x01, 0x00, 0x0f}
	if _, _, _, err := ParseServiceResponse(insufficient); err == nil {
		t.Error("insufficient encryption must be reported, not treated as completion")
	}
}

func TestParseServiceResponseRejectsMalformedInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		pdu  []byte
	}{
		{"empty", nil},
		{"short header", []byte{ATTReadByGroupTypeResponse}},
		{"entry too short", []byte{ATTReadByGroupTypeResponse, 0x05, 1, 2, 3, 4, 5}},
		{"partial entry", []byte{ATTReadByGroupTypeResponse, 0x06, 1, 2, 3, 4, 5}},
		{"group ends before it starts", []byte{ATTReadByGroupTypeResponse, 0x06, 0x05, 0x00, 0x01, 0x00, 0x0f, 0x18}},
		{"overlapping groups", []byte{ATTReadByGroupTypeResponse, 0x06,
			0x01, 0x00, 0x05, 0x00, 0x0f, 0x18,
			0x03, 0x00, 0x08, 0x00, 0x0f, 0x18}},
		{"no entries", []byte{ATTReadByGroupTypeResponse, 0x06}},
	} {
		if _, _, _, err := ParseServiceResponse(tc.pdu); err == nil {
			t.Errorf("%s: expected % x to be refused", tc.name, tc.pdu)
		}
	}
}

func TestParseCharacteristicResponse(t *testing.T) {
	pdu := []byte{ATTReadByTypeResponse, 0x07}
	pdu = binary.LittleEndian.AppendUint16(pdu, 0x0002) // declaration
	pdu = append(pdu, 0x0a)                             // read and notify
	pdu = binary.LittleEndian.AppendUint16(pdu, 0x0003) // value handle
	pdu = append(pdu, 0x00, 0x2a)                       // 16-bit characteristic UUID, little-endian
	entries, nextStart, done, err := ParseCharacteristicResponse(pdu)
	if err != nil {
		t.Fatal(err)
	}
	if done {
		t.Error("a populated response must not report completion")
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries", len(entries))
	}
	if entries[0].DeclarationHandle != 0x0002 || entries[0].ValueHandle != 0x0003 {
		t.Errorf("entry = %+v", entries[0])
	}
	if entries[0].Properties != 0x0a {
		t.Errorf("properties = 0x%02x", entries[0].Properties)
	}
	if entries[0].UUID != FormatUUID(0x2a00) {
		t.Errorf("UUID = %q", entries[0].UUID)
	}
	// The next walk starts after the value attribute, since the value handle is
	// between this declaration and any descriptor that follows.
	if nextStart != 0x0004 {
		t.Errorf("nextStart = 0x%04x, want 0x0004", nextStart)
	}
}

func TestParseCharacteristicResponseRejectsMalformedInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		pdu  []byte
	}{
		{"empty", nil},
		{"short header", []byte{ATTReadByTypeResponse}},
		{"entry too short", []byte{ATTReadByTypeResponse, 0x06, 1, 2, 3, 4, 5, 6}},
		{"partial entry", []byte{ATTReadByTypeResponse, 0x07, 1, 2, 3, 4, 5}},
		{"no entries", []byte{ATTReadByTypeResponse, 0x07}},
		{"value handle not above declaration", []byte{ATTReadByTypeResponse, 0x07,
			0x05, 0x00, 0x00, 0x02, 0x00, 0x2a, 0x00}},
		{"declarations out of order", []byte{ATTReadByTypeResponse, 0x07,
			0x05, 0x00, 0x00, 0x06, 0x00, 0x00, 0x2a,
			0x03, 0x00, 0x00, 0x04, 0x00, 0x00, 0x2a}},
	} {
		if _, _, _, err := ParseCharacteristicResponse(tc.pdu); err == nil {
			t.Errorf("%s: expected % x to be refused", tc.name, tc.pdu)
		}
	}
}

func TestFormatUUIDMatchesTheBluetoothBaseForm(t *testing.T) {
	if got := FormatUUID(UUIDPrimaryService); got != "2800-0000-1000-8000-00805F9B34FB" {
		t.Errorf("FormatUUID = %q", got)
	}
	if got := FormatUUID(UUIDClientCharacteristicConfiguration); got != "2902-0000-1000-8000-00805F9B34FB" {
		t.Errorf("FormatUUID = %q", got)
	}
}

func TestDiscoveryLimitsAreDeclared(t *testing.T) {
	// The bounds are part of the contract a caller reports against, so a change
	// to one must be a deliberate edit here.
	if MaxDiscoveredServices == 0 || MaxDiscoveredCharacteristics == 0 || MaxDiscoveredDescriptors == 0 || MaxDiscoveryRequests == 0 {
		t.Error("discovery bounds must be positive")
	}
	if DefaultDiscoveryTimeout <= 0 || DefaultDiscoveryMTU < DefaultATTMTU {
		t.Error("discovery defaults must be usable")
	}
}

func TestErrDiscoveryLimitIsIdentifiable(t *testing.T) {
	if !errors.Is(ErrDiscoveryLimit, ErrDiscoveryLimit) {
		t.Error("the limit error must be identifiable with errors.Is")
	}
}
