package bluetooth

import (
	"encoding/binary"
	"errors"
	"testing"
)

// serviceResponse builds a read-by-group-type response page listing services.
func serviceResponse(pages ...[3]any) []byte {
	pdu := []byte{ATTReadByGroupTypeResponse, 0x06}
	for _, page := range pages {
		pdu = binary.LittleEndian.AppendUint16(pdu, page[0].(uint16))
		pdu = binary.LittleEndian.AppendUint16(pdu, page[1].(uint16))
		pdu = append(pdu, byte(page[2].(uint16)), byte(page[2].(uint16)>>8))
	}
	return pdu
}

// characteristicResponse builds a read-by-type response page listing
// characteristics.
func characteristicResponse(pages ...[4]any) []byte {
	pdu := []byte{ATTReadByTypeResponse, 0x07}
	for _, page := range pages {
		pdu = binary.LittleEndian.AppendUint16(pdu, page[0].(uint16))
		pdu = append(pdu, page[1].(uint8))
		pdu = binary.LittleEndian.AppendUint16(pdu, page[2].(uint16))
		pdu = append(pdu, byte(page[3].(uint16)), byte(page[3].(uint16)>>8))
	}
	return pdu
}

// findResponse builds a find-information response page for 16-bit UUIDs.
func findResponse(handles ...uint16) []byte {
	pdu := []byte{ATTFindInformationResponse, 0x01}
	for _, handle := range handles {
		pdu = binary.LittleEndian.AppendUint16(pdu, handle)
		pdu = append(pdu, 0x02, 0x29) // Client Characteristic Configuration
	}
	return pdu
}

// notFound builds an ATT error response reporting attribute not found for a
// request, which is how a peer ends a range rather than an empty page.
func notFound(request byte) []byte {
	return []byte{ATTErrorResponse, request, 0xff, 0x00, 0x0a}
}

func TestDiscovererAssemblesAFullTable(t *testing.T) {
	d := NewDiscoverer("AA:BB:CC:DD:EE:FF")

	// Two services on one page, the first of which carries a read and notify
	// characteristic and the second a write-only characteristic.
	next, done, err := d.RecordServices(UUIDPrimaryService, serviceResponse(
		[3]any{uint16(0x0001), uint16(0x0005), uint16(0x180f)},
		[3]any{uint16(0x0006), uint16(0x0008), uint16(0x1801)},
	))
	if err != nil || done {
		t.Fatalf("service page: done=%v err=%v", done, err)
	}
	if next != 0x0009 {
		t.Errorf("the next page must start after the last group, got 0x%04x", next)
	}
	if _, done, err = d.RecordServices(UUIDPrimaryService, notFound(ATTReadByGroupTypeRequest)); err != nil || !done {
		t.Fatalf("attribute not found must end service discovery: done=%v err=%v", done, err)
	}

	// Characteristics are read for the whole table, so both services contribute.
	if _, _, err = d.RecordCharacteristics(characteristicResponse(
		[4]any{uint16(0x0002), uint8(0x12), uint16(0x0003), uint16(0x2a19)},
	)); err != nil {
		t.Fatal(err)
	}
	if _, _, err = d.RecordCharacteristics(characteristicResponse(
		[4]any{uint16(0x0007), uint8(0x08), uint16(0x0008), uint16(0x2a3e)},
	)); err != nil {
		t.Fatal(err)
	}
	if _, done, err = d.RecordCharacteristics(notFound(ATTReadByTypeRequest)); err != nil || !done {
		t.Fatalf("attribute not found must end characteristic discovery: done=%v err=%v", done, err)
	}

	// The descriptor range follows the first characteristic's value handle, and the
	// value attribute itself must not be recorded as a descriptor.
	if _, _, err = d.RecordAttributeRange(findResponse(0x0004, 0x0005), 0); err != nil {
		t.Fatal(err)
	}

	database, stats := d.Database()
	if stats.Services != 2 || stats.Characteristics != 2 || stats.Descriptors != 2 {
		t.Errorf("stats = %+v", stats)
	}
	if stats.Requests != 6 {
		t.Errorf("requests = %d, want 6", stats.Requests)
	}
	if stats.Truncated {
		t.Error("a complete walk must not report truncation")
	}
	if d.Truncated() {
		t.Error("the discoverer must not report truncation for a complete walk")
	}
	if database.DeviceAddress != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("address = %q", database.DeviceAddress)
	}
	if len(database.Services) != 2 {
		t.Fatalf("got %d services", len(database.Services))
	}
	first := database.Services[0]
	if !first.Primary || first.StartHandle != 0x0001 || first.EndHandle != 0x0005 {
		t.Errorf("first service = %+v", first)
	}
	if first.UUID != FormatUUID(0x180f) {
		t.Errorf("first service UUID = %q", first.UUID)
	}
	if len(first.Characteristics) != 1 {
		t.Fatalf("got %d characteristics on the first service", len(first.Characteristics))
	}
	readNotify := first.Characteristics[0]
	if readNotify.UUID != FormatUUID(0x2a19) || readNotify.Handle != 0x0003 {
		t.Errorf("characteristic = %+v", readNotify)
	}
	if !readNotify.Permissions.Read || readNotify.Permissions.Write {
		t.Errorf("properties 0x12 report read and notify only, got %+v", readNotify.Permissions)
	}
	if len(readNotify.Descriptors) != 2 {
		t.Errorf("got %d descriptors, want 2", len(readNotify.Descriptors))
	}
	second := database.Services[1]
	if len(second.Characteristics) != 1 {
		t.Fatalf("got %d characteristics on the second service", len(second.Characteristics))
	}
	writeOnly := second.Characteristics[0]
	if !writeOnly.Permissions.Write || writeOnly.Permissions.Read {
		t.Errorf("a write-only characteristic = %+v", writeOnly.Permissions)
	}
	if len(writeOnly.Descriptors) != 0 {
		t.Errorf("the second characteristic reported no descriptors, got %d", len(writeOnly.Descriptors))
	}
}

func TestDiscovererMapsEveryReportedProperty(t *testing.T) {
	d := NewDiscoverer("AA:BB:CC:DD:EE:FF")
	if _, _, err := d.RecordServices(UUIDPrimaryService, serviceResponse(
		[3]any{uint16(0x0001), uint16(0x0003), uint16(0x180f)},
	)); err != nil {
		t.Fatal(err)
	}
	// Broadcast, read, write without response, write, notify, and indicate.
	if _, _, err := d.RecordCharacteristics(characteristicResponse(
		[4]any{uint16(0x0002), uint8(0x3e), uint16(0x0003), uint16(0x2a19)},
	)); err != nil {
		t.Fatal(err)
	}
	database, _ := d.Database()
	characteristic := database.Services[0].Characteristics[0]
	if got := len(characteristic.Properties); got != 5 {
		t.Errorf("properties = %v, want the five reported access properties", characteristic.Properties)
	}
	if !characteristic.Permissions.Read || !characteristic.Permissions.Write {
		t.Errorf("permissions = %+v, want both read and write", characteristic.Permissions)
	}
}

func TestDiscovererStopsAtEachBound(t *testing.T) {
	// Each bound refuses the record that exceeds it and marks the walk truncated,
	// so a partial table is never reported as a peer's complete one.
	servicePage := func(handle uint16, uuid uint16) []byte {
		return serviceResponse([3]any{handle, handle, uuid})
	}
	characteristicPage := func(declaration, value, uuid uint16) []byte {
		return characteristicResponse([4]any{declaration, uint8(0x02), value, uuid})
	}

	t.Run("services", func(t *testing.T) {
		d := NewDiscovererWithLimits("AA:BB:CC:DD:EE:FF", DiscoveryLimits{Services: 1})
		if _, _, err := d.RecordServices(UUIDPrimaryService, servicePage(0x0001, 0x180f)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := d.RecordServices(UUIDPrimaryService, servicePage(0x0002, 0x1801)); !errors.Is(err, ErrDiscoveryLimit) {
			t.Fatalf("expected the service bound to refuse, got %v", err)
		}
		if !d.Truncated() {
			t.Error("a refused service must mark the walk truncated")
		}
		if _, stats := d.Database(); !stats.Truncated {
			t.Error("a truncated walk must be reported in the statistics")
		}
	})

	t.Run("characteristics", func(t *testing.T) {
		d := NewDiscovererWithLimits("AA:BB:CC:DD:EE:FF", DiscoveryLimits{Characteristics: 1})
		if _, _, err := d.RecordServices(UUIDPrimaryService, serviceResponse(
			[3]any{uint16(0x0001), uint16(0x0009), uint16(0x180f)},
		)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := d.RecordCharacteristics(characteristicPage(0x0002, 0x0003, 0x2a19)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := d.RecordCharacteristics(characteristicPage(0x0005, 0x0006, 0x2a1a)); !errors.Is(err, ErrDiscoveryLimit) {
			t.Fatalf("expected the characteristic bound to refuse, got %v", err)
		}
		if !d.Truncated() {
			t.Error("a refused characteristic must mark the walk truncated")
		}
		database, stats := d.Database()
		if stats.Characteristics != 1 || len(database.Services[0].Characteristics) != 1 {
			t.Errorf("a refused characteristic must not appear in the snapshot, got %+v", database.Services[0].Characteristics)
		}
	})

	t.Run("descriptors", func(t *testing.T) {
		// A descriptor always lies inside its service's handle range, so the group
		// end has to cover it.
		d := NewDiscovererWithLimits("AA:BB:CC:DD:EE:FF", DiscoveryLimits{Descriptors: 1})
		if _, _, err := d.RecordServices(UUIDPrimaryService, serviceResponse(
			[3]any{uint16(0x0001), uint16(0x0005), uint16(0x180f)},
		)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := d.RecordCharacteristics(characteristicPage(0x0002, 0x0003, 0x2a19)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := d.RecordAttributeRange(findResponse(0x0004), 0); err != nil {
			t.Fatal(err)
		}
		if _, _, err := d.RecordAttributeRange(findResponse(0x0005), 0); !errors.Is(err, ErrDiscoveryLimit) {
			t.Fatalf("expected the descriptor bound to refuse, got %v", err)
		}
		database, stats := d.Database()
		if !stats.Truncated {
			t.Error("a truncated walk must be reported in the statistics")
		}
		if stats.Descriptors != 1 || len(database.Services[0].Characteristics[0].Descriptors) != 1 {
			t.Errorf("a refused descriptor must not appear in the snapshot, got %+v", database.Services[0].Characteristics[0].Descriptors)
		}
	})
}

func TestDiscovererRefusesTheServiceBound(t *testing.T) {
	d := NewDiscovererWithLimits("AA:BB:CC:DD:EE:FF", DiscoveryLimits{Services: 2})
	if _, _, err := d.RecordServices(UUIDPrimaryService, serviceResponse(
		[3]any{uint16(0x0001), uint16(0x0001), uint16(0x180f)},
		[3]any{uint16(0x0002), uint16(0x0002), uint16(0x1801)},
	)); err != nil {
		t.Fatal(err)
	}
	_, _, err := d.RecordServices(UUIDPrimaryService, serviceResponse(
		[3]any{uint16(0x0003), uint16(0x0003), uint16(0x1802)},
	))
	if !errors.Is(err, ErrDiscoveryLimit) {
		t.Fatalf("expected the service bound to refuse, got %v", err)
	}
	if !d.Truncated() {
		t.Error("a refused service must mark the walk truncated")
	}
	if _, stats := d.Database(); !stats.Truncated {
		t.Error("truncation must be visible in the reported statistics")
	}
}

func TestDiscovererRefusesTheDescriptorBound(t *testing.T) {
	d := NewDiscovererWithLimits("AA:BB:CC:DD:EE:FF", DiscoveryLimits{Descriptors: 1})
	if _, _, err := d.RecordServices(UUIDPrimaryService, serviceResponse(
		[3]any{uint16(0x0001), uint16(0x0003), uint16(0x180f)},
	)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.RecordCharacteristics(characteristicResponse(
		[4]any{uint16(0x0002), uint8(0x02), uint16(0x0003), uint16(0x2a19)},
	)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.RecordAttributeRange(findResponse(0x0004), 1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.RecordAttributeRange(findResponse(0x0005), 1); !errors.Is(err, ErrDiscoveryLimit) {
		t.Fatalf("expected the descriptor bound to refuse, got %v", err)
	}
}

func TestDiscovererRefusesTheRequestBound(t *testing.T) {
	d := NewDiscovererWithLimits("AA:BB:CC:DD:EE:FF", DiscoveryLimits{Requests: 2})
	page := serviceResponse([3]any{uint16(0x0001), uint16(0x0001), uint16(0x180f)})
	if _, _, err := d.RecordServices(UUIDPrimaryService, page); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.RecordServices(UUIDPrimaryService, page); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.RecordServices(UUIDPrimaryService, page); !errors.Is(err, ErrDiscoveryLimit) {
		t.Fatalf("expected the request bound to refuse, got %v", err)
	}
}

func TestDiscovererPropagatesMalformedResponses(t *testing.T) {
	d := NewDiscoverer("AA:BB:CC:DD:EE:FF")
	if _, _, err := d.RecordServices(UUIDPrimaryService, []byte{ATTReadByGroupTypeResponse, 0x06, 1}); err == nil {
		t.Error("a malformed service page must be reported")
	}
	if _, _, err := d.RecordCharacteristics([]byte{ATTReadByTypeResponse, 0x07, 1}); err == nil {
		t.Error("a malformed characteristic page must be reported")
	}
	if _, _, err := d.RecordAttributeRange([]byte{ATTFindInformationResponse, 0x03, 1, 2}, 0); err == nil {
		t.Error("a malformed descriptor page must be reported")
	}
}

func TestDiscovererTreatsEncryptionFailureAsAnError(t *testing.T) {
	d := NewDiscoverer("AA:BB:CC:DD:EE:FF")
	// A peer that requires encryption answers with insufficient encryption. That is
	// a refusal by the peer, not the end of the table, so it must surface.
	pdu := []byte{ATTErrorResponse, ATTReadByTypeRequest, 0x01, 0x00, 0x0f}
	if _, _, err := d.RecordCharacteristics(pdu); err == nil {
		t.Error("insufficient encryption must be reported rather than ending discovery")
	}
}

func TestDiscovererDoesNotCountValueAttributesAsDescriptors(t *testing.T) {
	d := NewDiscoverer("AA:BB:CC:DD:EE:FF")
	if _, _, err := d.RecordServices(UUIDPrimaryService, serviceResponse(
		[3]any{uint16(0x0001), uint16(0x0003), uint16(0x180f)},
	)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.RecordCharacteristics(characteristicResponse(
		[4]any{uint16(0x0002), uint8(0x02), uint16(0x0003), uint16(0x2a19)},
	)); err != nil {
		t.Fatal(err)
	}
	database, stats := d.Database()
	if stats.Descriptors != 0 {
		t.Errorf("a value attribute must not be counted as a descriptor, got %d", stats.Descriptors)
	}
	if len(database.Services[0].Characteristics[0].Descriptors) != 0 {
		t.Error("a value attribute must not be attached as a descriptor")
	}
}

func TestDiscovererIgnoresAnIncludeDeclaration(t *testing.T) {
	d := NewDiscoverer("AA:BB:CC:DD:EE:FF")
	if _, _, err := d.RecordServices(UUIDPrimaryService, serviceResponse(
		[3]any{uint16(0x0001), uint16(0x0002), uint16(0x1809)},
	)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.RecordAttributeRange([]byte{ATTFindInformationResponse, 0x01,
		0x02, 0x00, 0x02, 0x28}, 0); err != nil { // 0x2802 is an include declaration
		t.Fatal(err)
	}
	database, stats := d.Database()
	if stats.Descriptors != 0 {
		t.Errorf("an include declaration must not become a descriptor, got %d", stats.Descriptors)
	}
	if len(database.Services[0].Characteristics) != 0 {
		t.Errorf("an include must not become a characteristic, got %+v", database.Services[0].Characteristics)
	}
}

func TestDiscoveryLimitsDefaultRatherThanDisable(t *testing.T) {
	limits := DiscoveryLimits{}.withDefaults()
	if limits.Services != MaxDiscoveredServices || limits.Characteristics != MaxDiscoveredCharacteristics ||
		limits.Descriptors != MaxDiscoveredDescriptors || limits.Requests != MaxDiscoveryRequests {
		t.Errorf("defaults = %+v", limits)
	}
	custom := DiscoveryLimits{Services: 3}.withDefaults()
	if custom.Services != 3 {
		t.Errorf("an explicit bound must be kept, got %d", custom.Services)
	}
	if custom.Descriptors != MaxDiscoveredDescriptors {
		t.Errorf("an unset bound must take the default, got %d", custom.Descriptors)
	}
}

func TestDatabaseKeepsAGenericServiceDistinctFromAServiceDeclaration(t *testing.T) {
	d := NewDiscoverer("AA:BB:CC:DD:EE:FF")
	// A service declaration reports type 0x2800 and the UUID of the service. A
	// generic attribute that merely carries a 0x2800-looking value must not be
	// mistaken for one.
	if _, _, err := d.RecordServices(UUIDPrimaryService, serviceResponse(
		[3]any{uint16(0x0001), uint16(0x0001), uint16(0x180f)},
	)); err != nil {
		t.Fatal(err)
	}
	database, _ := d.Database()
	if len(database.Services) != 1 || database.Services[0].UUID != FormatUUID(0x180f) {
		t.Errorf("services = %+v", database.Services)
	}
	if d.Services(UUIDPrimaryService) != 1 {
		t.Errorf("recorded services = %d, want 1", d.Services(UUIDPrimaryService))
	}
}

func TestAttributesIsACopy(t *testing.T) {
	d := NewDiscoverer("AA:BB:CC:DD:EE:FF")
	if _, _, err := d.RecordServices(UUIDPrimaryService, serviceResponse(
		[3]any{uint16(0x0001), uint16(0x0001), uint16(0x180f)},
	)); err != nil {
		t.Fatal(err)
	}
	attributes := d.Attributes()
	if len(attributes) != 1 {
		t.Fatalf("got %d attributes", len(attributes))
	}
	attributes[0].UUID = "tampered"
	if d.Attributes()[0].UUID == "tampered" {
		t.Error("Attributes must return a copy so a caller cannot rewrite the record")
	}
}
