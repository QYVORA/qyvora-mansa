//go:build linux

package transport

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/QYVORA/qyvora-mansa/pkg/models"
	"golang.org/x/sys/unix"
)

// Link Control and LE Control opcodes used for read-only controller queries.
// Every command here only reads controller state: none enables scanning,
// changes power, or pairs.
const (
	hciOGFLinkControl = 0x04

	hciOCFReadLocalVersion         = 0x0001
	hciOCFReadLocalCommands        = 0x0002
	hciOCFReadLocalSupportedFeat   = 0x0003
	hciOCFReadBDAddr               = 0x0005
	hciOCFLEReadBufferSize         = 0x0002
	hciOCFLEReadLocalSupportedFeat = 0x0003
)

// hciVersionNames maps the HCI version number a controller reports to its
// specification name.
var hciVersionNames = map[uint8]string{
	0: "1.0b", 1: "1.1", 2: "1.2", 3: "2.0+EDR", 4: "2.1+EDR", 5: "3.0+HS",
	6: "4.0", 7: "4.1", 8: "4.2", 9: "5.0", 10: "5.1", 11: "5.2", 12: "5.3", 13: "5.4", 14: "6.0",
}

// lmpVersionNames maps the Link Manager Protocol version to its era name.
var lmpVersionNames = map[uint8]string{
	1: "1.0b", 2: "1.1", 3: "1.2", 4: "2.0+EDR", 5: "2.1+EDR", 6: "3.0+HS",
	7: "4.0", 8: "4.1", 9: "4.2", 10: "5.0", 11: "5.1", 12: "5.2", 13: "5.3",
}

// leFeatureNames is the subset of LE feature bits Mansa names. The bits are
// stable positions in the controller's LE_Features field; a bit that is not
// listed here is reported as set only in the raw bitmap the controller sent.
var leFeatureNames = map[uint]struct {
	bit  uint
	name string
}{
	0:  {0, "LE Encryption"},
	1:  {1, "LE Connection Parameter Request Procedure"},
	2:  {2, "LE Extended Reject Indication"},
	3:  {3, "LE Peripheral Initiated Features Exchange"},
	4:  {4, "LE Ping"},
	5:  {5, "LE Data Packet Length Extension"},
	6:  {6, "LE LL Privacy"},
	7:  {7, "LE Extended Scanner Filter Policies"},
	8:  {8, "LE 8 Bit Advertising Address Types"},
	9:  {9, "LE Advertising Channel Indication"},
	10: {10, "LE Link Layer Initiated Feature Exchange"},
	11: {11, "LE Extended Initiator Indication"},
	12: {12, "LE Periodic Advertising"},
	13: {13, "LE Secure Connections Only Mode"},
	14: {14, "LE Extended Advertising"},
	15: {15, "LE 2M PHY"},
	16: {16, "LE Stable Modulation Index Transmitter"},
	17: {17, "LE Stable Modulation Index Receiver"},
	18: {18, "LE Extended Feature Set"},
	23: {23, "LE Periodic Advertising Improved"},
	24: {24, "LE Channel Selection Algorithm #2"},
	29: {29, "LE Power Control"},
}

// ControllerInfo reads controller identity and LE capability metadata using
// read-only HCI commands. It does not enable scanning, change power state, or
// pair with anything.
func (b *LinuxBackend) ControllerInfo(ctx context.Context, adapter string) (models.BluetoothControllerInfo, error) {
	info := models.BluetoothControllerInfo{Adapter: adapter}
	index, err := parseHCIIndex(adapter)
	if err != nil {
		return info, err
	}
	fd, err := unix.Socket(unix.AF_BLUETOOTH, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.BTPROTO_HCI)
	if err != nil {
		return info, fmt.Errorf("open HCI socket (CAP_NET_RAW may be required): %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrHCI{Dev: uint16(index), Channel: unix.HCI_CHANNEL_RAW}); err != nil {
		return info, fmt.Errorf("bind HCI adapter %s: %w", adapter, err)
	}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 200000}); err != nil {
		return info, fmt.Errorf("set HCI receive timeout: %w", err)
	}

	read := func(name string, ogf, ocf uint16, minimum int) ([]byte, error) {
		data, err := sendHCICommandForData(fd, ctx, ogf, ocf, nil)
		if err != nil {
			info.Unreadable = append(info.Unreadable, name)
			return nil, nil
		}
		if len(data) < minimum {
			info.Unreadable = append(info.Unreadable, fmt.Sprintf("%s (short reply: %d bytes)", name, len(data)))
			return nil, nil
		}
		return data, nil
	}

	// Read Local Version Information returns status, HCI version, LMP version,
	// company identifier, and LMP subversion.
	if data, err := read("Read Local Version Information", hciOGFLinkControl, hciOCFReadLocalVersion, 8); err != nil {
		return info, err
	} else if data != nil {
		info.HCIVersion = data[1]
		info.LMPVersion = data[2]
		info.Manufacturer = binary.LittleEndian.Uint16(data[3:5])
		info.HCIVersionName = hciVersionNames[info.HCIVersion]
		if info.HCIVersionName == "" {
			info.HCIVersionName = fmt.Sprintf("reserved 0x%02x", info.HCIVersion)
		}
		info.LMPVersionName = lmpVersionNames[info.LMPVersion]
		info.CompanyName = bluetoothCompanyName(info.Manufacturer)
	}
	if data, err := read("Read BD_ADDR", hciOGFLinkControl, hciOCFReadBDAddr, 6); err != nil {
		return info, err
	} else if data != nil {
		info.Address = formatBDAddr(data[:6])
	}
	// Read Local Supported Commands returns the 64-octet command bitmap.
	if data, err := read("Read Local Supported Commands", hciOGFLinkControl, hciOCFReadLocalCommands, 64); err != nil {
		return info, err
	} else if data != nil {
		info.SupportedCommandsHex = hex.EncodeToString(data[:64])
	}
	if data, err := read("LE Read Buffer Size", hciOGFLEControl, hciOCFLEReadBufferSize, 2); err != nil {
		return info, err
	} else if data != nil {
		info.LEBufferLength = data[1]
		info.LEPackets = data[2]
	}
	if data, err := read("LE Read Local Supported Features", hciOGFLEControl, hciOCFLEReadLocalSupportedFeat, 8); err != nil {
		return info, err
	} else if data != nil {
		info.LEFeatures = decodeLEFeatures(data[:8])
	}
	if len(info.Unreadable) > 0 {
		info.Unreadable = append(info.Unreadable, fmt.Sprintf("%d of 5 controller queries returned no data", len(info.Unreadable)))
	}
	return info, nil
}

// decodeLEFeatures names the LE feature bits a controller reports as set,
// returning them in bit order so the output is stable.
func decodeLEFeatures(bits []byte) []string {
	if len(bits) != 8 {
		return nil
	}
	bitmap := binary.LittleEndian.Uint64(bits)
	ordered := make([]struct {
		bit  uint
		name string
	}, 0, len(leFeatureNames))
	for _, entry := range leFeatureNames {
		ordered = append(ordered, entry)
	}
	// Sort by bit without importing sort into every caller.
	for i := 1; i < len(ordered); i++ {
		for j := i; j > 0 && ordered[j].bit < ordered[j-1].bit; j-- {
			ordered[j], ordered[j-1] = ordered[j-1], ordered[j]
		}
	}
	var out []string
	for _, entry := range ordered {
		if bitmap&(1<<entry.bit) != 0 {
			out = append(out, entry.name)
		}
	}
	return out
}

// formatBDAddr renders a controller address in the conventional
// upper-case, most-significant-octet-last form the specification uses for BD_ADDR.
func formatBDAddr(b []byte) string {
	if len(b) != 6 {
		return ""
	}
	parts := make([]string, 6)
	for i := 0; i < 6; i++ {
		parts[i] = fmt.Sprintf("%02X", b[5-i])
	}
	return strings.Join(parts, ":")
}

// bluetoothCompanyNames is the assigned-numbers subset Mansa names. An
// unlisted identifier is reported as its numeric value.
var bluetoothCompanyNames = map[uint16]string{
	0x0001: "Microsoft",
	0x0002: "IBM",
	0x0003: "Intel",
	0x0004: "Motorola",
	0x0005: "Infineon",
	0x0006: "Cambridge Silicon Radio",
	0x0007: "Silicon Wave",
	0x0008: "Digianswer",
	0x0009: "Texas Instruments",
	0x000F: "Broadcom",
	0x0012: "Zeevo",
	0x0013: "Atmel",
	0x0015: "Open Interface",
	0x001D: "Qualcomm",
	0x0025: "Alcatel",
	0x002F: "Nordic Semiconductor",
	0x0036: "Realtek",
	0x003D: "Qualcomm",
	0x004C: "Apple",
	0x005D: "Realtek",
	0x005F: "Nordic Semiconductor",
	0x0087: "Garmin",
	0x00E0: "Google",
	0x05B7: "Espressif",
}

func bluetoothCompanyName(id uint16) string {
	if name, ok := bluetoothCompanyNames[id]; ok {
		return name
	}
	return fmt.Sprintf("company 0x%04x", id)
}
