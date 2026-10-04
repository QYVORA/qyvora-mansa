package bluetooth

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// BLE advertising data type codes, from the Core Specification Supplement,
// Part A, section 2.3.
const (
	adTypeFlags                  = 0x01
	adTypeIncompleteUUID16       = 0x02
	adTypeCompleteUUID16         = 0x03
	adTypeIncompleteUUID32       = 0x04
	adTypeCompleteUUID32         = 0x05
	adTypeIncompleteUUID128      = 0x06
	adTypeCompleteUUID128        = 0x07
	adTypeShortenedLocalName     = 0x08
	adTypeCompleteLocalName      = 0x09
	adTypeTXPowerLevel           = 0x0a
	adTypeClassOfDevice          = 0x0d
	adTypeServiceData            = 0x16
	adTypeManufacturerData       = 0xff
	adTypeURI                    = 0x24
	adTypeServiceSolicitation16  = 0x14
	adTypeServiceSolicitation128 = 0x1f
)

// HCI event and subevent codes for LE advertising reports. A raw HCI socket
// delivers events without the H4 type byte, so the event code comes first.
const (
	hciEventLEMeta           = 0x3e
	hciSubeventLEAdvReport   = 0x02
	hciSubeventLEExtendedAdv = 0x0d
	hciSubeventLEReport      = 0x03
	extendedAdvMaxReports    = 8
	advReportAddressBytes    = 6
	advReportDataLengthMax   = 229
	extendedAdvDataLengthMax = 229
)

// addressTypePublic and friends are the LE advertising report address types.
const (
	addressTypePublic   = 0x00
	addressTypeRandom   = 0x01
	addressTypeIdentity = 0x02
)

// ParseAdvertisement decodes a BLE advertising payload into its normalized
// fields.
//
// An unknown data type is skipped rather than refused. Advertising payloads are
// extensible by design, so an unrecognised type is a device using a feature this
// decoder does not model, not a malformed frame. A type whose length runs past
// the end of the payload is an error, because that means the frame is truncated
// and silently stopping would understate what was there.
func ParseAdvertisement(payload []byte) (models.BLEAdvertisement, error) {
	advertisement := models.BLEAdvertisement{}
	completeName := ""
	for offset := 0; offset < len(payload); {
		// A zero length or type terminates the significant part of the payload
		// per the specification; the remainder is padding.
		length := int(payload[offset])
		if length == 0 {
			break
		}
		if offset+1+length > len(payload) {
			return models.BLEAdvertisement{}, fmt.Errorf("advertising type 0x%02x at offset %d claims %d bytes but only %d remain", payload[offset+1], offset, length, len(payload)-offset-1)
		}
		code := payload[offset+1]
		data := payload[offset+2 : offset+1+length]

		switch code {
		case adTypeIncompleteUUID16, adTypeCompleteUUID16,
			adTypeIncompleteUUID32, adTypeCompleteUUID32,
			adTypeIncompleteUUID128, adTypeCompleteUUID128:
			uuid, err := parseAdvertisedUUID(data)
			if err != nil {
				return models.BLEAdvertisement{}, err
			}
			advertisement.ServiceUUIDs = append(advertisement.ServiceUUIDs, uuid)
		case adTypeShortenedLocalName:
			if advertisement.Name == "" {
				advertisement.Name = sanitizeLocalName(data)
			}
		case adTypeCompleteLocalName:
			completeName = sanitizeLocalName(data)
			advertisement.Name = completeName
		case adTypeTXPowerLevel:
			if len(data) != 1 {
				return models.BLEAdvertisement{}, fmt.Errorf("TX power level must carry one byte, got %d", len(data))
			}
			power := int8(data[0])
			advertisement.TxPower = &power
		case adTypeManufacturerData:
			if len(data) < 2 {
				return models.BLEAdvertisement{}, fmt.Errorf("manufacturer data needs a two byte company identifier, got %d bytes", len(data))
			}
			company := binary.LittleEndian.Uint16(data[:2])
			if advertisement.ManufacturerData == nil {
				advertisement.ManufacturerData = make(map[uint16][]byte)
			}
			advertisement.ManufacturerData[company] = append([]byte(nil), data[2:]...)
		}
		offset += 1 + length
	}
	advertisement.CompleteName = completeName != ""
	if completeName != "" {
		advertisement.Name = completeName
	}
	return advertisement, nil
}

// sanitizeLocalName drops the trailing NUL some controllers append, so the name
// compares equal regardless of which stack reported it.
func sanitizeLocalName(data []byte) string {
	return strings.TrimRight(string(data), "\x00")
}

// parseAdvertisedUUID decodes a 16, 32, or 128 bit service UUID. Service UUIDs
// on the air are little endian.
func parseAdvertisedUUID(data []byte) (string, error) {
	switch len(data) {
	case 2:
		return FormatUUID(binary.LittleEndian.Uint16(data)), nil
	case 4:
		value := binary.LittleEndian.Uint32(data)
		return formatUUID32(value), nil
	case 16:
		return formatUUID128(data), nil
	default:
		return "", fmt.Errorf("advertised service UUID has %d bytes, want 2, 4, or 16", len(data))
	}
}

// formatUUID32 renders a 32 bit service UUID in the Bluetooth base form, which
// expands it to the 0000xxxx-0000-1000-8000-00805f9b34fb range.
func formatUUID32(value uint32) string {
	return fmt.Sprintf("%08X-0000-1000-8000-00805F9B34FB", value)
}

// formatUUID128 renders a little-endian 128 bit UUID in the Bluetooth base form.
func formatUUID128(little []byte) string {
	var reversed [16]byte
	for i := range little {
		reversed[15-i] = little[i]
	}
	return fmt.Sprintf("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		reversed[0], reversed[1], reversed[2], reversed[3],
		reversed[4], reversed[5], reversed[6], reversed[7],
		reversed[8], reversed[9], reversed[10], reversed[11],
		reversed[12], reversed[13], reversed[14], reversed[15])
}

// SimulatedAdvertisementData returns a deterministic advertising payload. It
// carries a complete local name, a 16 bit service UUID, a TX power level, and
// manufacturer data, so a simulated run exercises every decoder branch.
//
// Each field is length, type, data: the length counts the type byte as well as
// the data, which is what the specification requires and what the decoder above
// expects.
func SimulatedAdvertisementData() []byte {
	payload := []byte{
		0x02, adTypeFlags, 0x06, // LE General Discoverable
		0x03, adTypeCompleteUUID16, 0x0f, 0x18, // service UUID 0x180f, little endian on air
		byte(1 + len("Mansa Sim")), adTypeCompleteLocalName,
	}
	payload = append(payload, []byte("Mansa Sim")...)
	payload = append(payload, 0x02, adTypeTXPowerLevel, 0xe4)                 // -28 dBm
	payload = append(payload, 0x04, adTypeManufacturerData, 0x4c, 0x00, 0x4d) // company 0x004c
	return payload
}

// ParseLEAdvertisingReports decodes an HCI LE Meta advertising report event,
// including the extended form that carries secondary PHY and SID information.
//
// A packet that is not an advertising report is an error rather than an empty
// result: the caller passed something specific, and returning nothing would read
// as "no devices were nearby".
func ParseLEAdvertisingReports(packet []byte) ([]models.BluetoothDeviceObservation, error) {
	event, parameters, err := hciEventParameters(packet)
	if err != nil {
		return nil, err
	}
	if event != hciEventLEMeta {
		return nil, fmt.Errorf("HCI event 0x%02x is not an LE Meta event", event)
	}
	if len(parameters) < 1 {
		return nil, fmt.Errorf("LE Meta event carries no subevent code")
	}
	subevent := parameters[0]

	switch subevent {
	case hciSubeventLEAdvReport:
		return parseLegacyAdvertisingReport(parameters[1:])
	case hciSubeventLEExtendedAdv:
		return parseExtendedAdvertisingReports(parameters[1:])
	default:
		return nil, fmt.Errorf("LE subevent 0x%02x does not carry advertising reports", subevent)
	}
}

// hciPacketTypeEvent is the H4 packet type byte that precedes an HCI event on a
// Bluetooth socket.
const hciPacketTypeEvent = 0x04

// hciEventPayload strips H4 framing and returns the event code and parameters.
//
// A Linux HCI socket delivers each event as a type byte, a one-byte parameter
// length, the event code, and the parameters. A capture assembled from a test or
// from a decoded log often starts at the event code instead. Both are accepted,
// because refusing the framed form would refuse the packets a real capture holds.
func hciEventParameters(packet []byte) (byte, []byte, error) {
	if len(packet) == 0 {
		return 0, nil, fmt.Errorf("HCI packet is empty")
	}
	if packet[0] != hciPacketTypeEvent {
		if len(packet) < 2 {
			return 0, nil, fmt.Errorf("HCI packet of %d bytes is too short to carry an event code", len(packet))
		}
		// Unframed: the event code is the first byte.
		return packet[0], packet[1:], nil
	}
	if len(packet) < 3 {
		return 0, nil, fmt.Errorf("framed HCI packet of %d bytes is too short to carry an event code", len(packet))
	}
	event := packet[1]
	declared := int(packet[2])
	// The declared length counts the parameters only. A packet shorter than that
	// is refused rather than parsed as far as it goes: a truncated event would
	// report a shorter advertising payload than the controller actually sent.
	if len(packet)-3 < declared {
		return 0, nil, fmt.Errorf("framed HCI packet declares %d parameter byte(s) but carries %d", declared, len(packet)-3)
	}
	return event, packet[3 : 3+declared], nil
}

// parseLegacyAdvertisingReport decodes the LE Advertising Report subevent, whose
// parameter block holds a report count and then that many variable-length
// reports.
func parseLegacyAdvertisingReport(parameters []byte) ([]models.BluetoothDeviceObservation, error) {
	if len(parameters) < 1 {
		return nil, fmt.Errorf("LE Advertising Report carries no report count")
	}
	count := int(parameters[0])
	offset := 1
	observations := make([]models.BluetoothDeviceObservation, 0, count)
	for i := 0; i < count; i++ {
		// event type (1), address type (1), address (6), data length (1),
		// data (n), RSSI (1).
		if offset+1+advReportAddressBytes+1 > len(parameters) {
			return nil, fmt.Errorf("advertising report %d is truncated at offset %d", i, offset)
		}
		eventType := uint16(parameters[offset])
		addressType := parameters[offset+1]
		address := formatBDAddrBytes(parameters[offset+2 : offset+2+advReportAddressBytes])
		offset += 2 + advReportAddressBytes

		dataLength := int(parameters[offset])
		offset++
		if offset+dataLength+1 > len(parameters) {
			return nil, fmt.Errorf("advertising report %d claims %d data bytes but only %d remain", i, dataLength, len(parameters)-offset)
		}
		advertisement, err := ParseAdvertisement(parameters[offset : offset+dataLength])
		if err != nil {
			return nil, fmt.Errorf("advertising report %d: %w", i, err)
		}
		offset += dataLength

		observation := models.BluetoothDeviceObservation{
			Address:       address,
			AddressType:   addressType,
			EventType:     eventType,
			Advertisement: advertisement,
		}
		// RSSI is one signed byte; the top bit means the value is not available
		// and must not be reported as a level.
		if rssi := int8(parameters[offset]); rssi != 127 {
			observation.RSSI = rssi
			observation.RSSIAvailable = true
		}
		offset++
		observations = append(observations, observation)
	}
	return observations, nil
}

// parseExtendedAdvertisingReports decodes the LE Extended Advertising Report
// subevent, whose reports carry a SID, primary and secondary PHY, and a data
// status alongside the address and payload.
func parseExtendedAdvertisingReports(parameters []byte) ([]models.BluetoothDeviceObservation, error) {
	if len(parameters) < 2 {
		return nil, fmt.Errorf("LE Extended Advertising Report carries no report count")
	}
	count := int(parameters[1])
	offset := 2
	observations := make([]models.BluetoothDeviceObservation, 0, count)
	for i := 0; i < count && i < extendedAdvMaxReports; i++ {
		// event type (2), subevent type (1), address type (1), address (6),
		// primary PHY (1), secondary PHY (1), SID (1), TX power (1), RSSI (1),
		// data status (1), data length (1), data (n).
		if offset+2+1+1+advReportAddressBytes+6+1 > len(parameters) {
			return nil, fmt.Errorf("extended advertising report %d is truncated at offset %d", i, offset)
		}
		eventType := binary.LittleEndian.Uint16(parameters[offset:])
		addressType := parameters[offset+3]
		address := formatBDAddrBytes(parameters[offset+4 : offset+4+advReportAddressBytes])
		primaryPHY := parameters[offset+4+advReportAddressBytes]
		secondaryPHY := parameters[offset+5+advReportAddressBytes]
		sid := parameters[offset+6+advReportAddressBytes]
		txPowerRaw := int8(parameters[offset+7+advReportAddressBytes])
		rssiRaw := int8(parameters[offset+8+advReportAddressBytes])
		dataStatus := parameters[offset+9+advReportAddressBytes]
		offset += 10 + advReportAddressBytes

		dataLength := int(parameters[offset])
		offset++
		if offset+dataLength > len(parameters) {
			return nil, fmt.Errorf("extended advertising report %d claims %d data bytes but only %d remain", i, dataLength, len(parameters)-offset)
		}
		advertisement, err := ParseAdvertisement(parameters[offset : offset+dataLength])
		if err != nil {
			return nil, fmt.Errorf("extended advertising report %d: %w", i, err)
		}
		offset += dataLength

		observation := models.BluetoothDeviceObservation{
			Address:        address,
			AddressType:    addressType,
			EventType:      eventType,
			PrimaryPHY:     primaryPHY,
			SecondaryPHY:   secondaryPHY,
			AdvertisingSID: sid,
			DataStatus:     dataStatusName(dataStatus),
			Advertisement:  advertisement,
		}
		// 127 means "not available" for both signed fields, so neither may be
		// reported as a measured level.
		if rssiRaw != 127 {
			observation.RSSI = rssiRaw
			observation.RSSIAvailable = true
		}
		if txPowerRaw != 127 {
			txPower := txPowerRaw
			observation.TxPower = &txPower
		}
		observations = append(observations, observation)
	}
	return observations, nil
}

// dataStatusName renders the controller's data status as a word rather than a
// bare number, because the values mean different things: complete, incomplete,
// and truncated data lead to different conclusions.
func dataStatusName(status byte) string {
	switch status & 0x03 {
	case 0x00:
		return "complete"
	case 0x01:
		return "incomplete"
	case 0x02:
		return "truncated"
	default:
		return "reserved"
	}
}

// formatBDAddrBytes renders six little-endian address bytes in the canonical
// reversed order Bluetooth uses on the air.
func formatBDAddrBytes(little []byte) string {
	if len(little) != advReportAddressBytes {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		little[5], little[4], little[3], little[2], little[1], little[0])
}

// SimulatedLEAdvertisingReport returns a deterministic HCI LE Meta advertising
// report packet. It is the packet a capture would deliver, not a parsed
// observation, so a simulated run exercises the same decoder a real capture does.
func SimulatedLEAdvertisingReport() []byte {
	payload := SimulatedAdvertisementData()
	parameters := make([]byte, 0, 2+advReportAddressBytes+1+len(payload)+1)
	parameters = append(parameters, 0x01)                               // one report
	parameters = append(parameters, 0x03)                               // event type: ADV_IND
	parameters = append(parameters, addressTypePublic)                  // address type
	parameters = append(parameters, 0x6b, 0x8c, 0x4f, 0x2a, 0x11, 0x05) // address, on-air order
	parameters = append(parameters, byte(len(payload)))
	parameters = append(parameters, payload...)
	parameters = append(parameters, 0xc4) // RSSI -60 dBm

	packet := []byte{hciEventLEMeta, hciSubeventLEAdvReport}
	packet = append(packet, parameters...)
	return packet
}
