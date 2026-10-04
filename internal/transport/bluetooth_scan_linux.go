//go:build linux

package transport

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-mansa/internal/bluetooth"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
	"golang.org/x/sys/unix"
)

// leScanDefaultTimeout bounds a read when the controller goes quiet, so a
// passive scan cannot block forever on a silent adapter.
const leScanDefaultTimeout = 2 * time.Second

// DiscoverBluetoothAdapters lists the host's HCI adapters from sysfs.
//
// It is strictly read-only: it opens no socket, sends no command, and never
// powers an adapter on. An adapter that exists but is not usable is still
// listed, with the state sysfs reports, because "present" and "ready" are
// different questions and the capability report asks both.
func (b *LinuxBackend) DiscoverBluetoothAdapters() ([]models.BluetoothAdapter, error) {
	root := "/sys/class/bluetooth"
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			// No Bluetooth subsystem is a fact about the host, not a failure.
			return nil, nil
		}
		return nil, fmt.Errorf("list Bluetooth adapters: %w", err)
	}
	adapters := make([]models.BluetoothAdapter, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		adapter := models.BluetoothAdapter{ID: name, Type: "hci"}
		adapter.Address = readSysfsAttribute(filepath.Join(root, name, "address"))
		// device/ is a symlink to the USB or platform device behind the adapter.
		device := filepath.Join(root, name, "device")
		if resolved, resolveErr := filepath.EvalSymlinks(device); resolveErr == nil {
			device = resolved
		}
		if driver, err := os.ReadFile(filepath.Join(device, "driver", "uevent")); err == nil {
			adapter.Driver = sysfsUEVENTValue(string(driver), "DRIVER")
		}
		// PRODUCT in uevent is "bus:vendor:product", so the vendor is a field of
		// it rather than the whole string. Prefer the device's own idVendor.
		adapter.VendorID = sysfsHexAttribute(filepath.Join(device, "idVendor"))
		if adapter.VendorID == "" {
			if product := sysfsUEVENTValue(readSysfsAttribute(filepath.Join(device, "uevent")), "PRODUCT"); product != "" {
				if _, vendor, ok := strings.Cut(product, ":"); ok {
					adapter.VendorID = sysfsHexAttributeValue(vendor)
				}
			}
		}
		adapter.ProductID = sysfsHexAttribute(filepath.Join(device, "idProduct"))
		adapter.State = hciAdapterState(root, name, adapter.Address)
		adapters = append(adapters, adapter)
	}
	sort.Slice(adapters, func(i, j int) bool { return adapters[i].ID < adapters[j].ID })
	return adapters, nil
}

// hciAdapterState names what sysfs says about one adapter without opening it, so
// an adapter that is present but down is reported as down.
//
// root and name identify the adapter's own sysfs directory. Reading some other
// adapter's directory would report every adapter's state from whichever happened
// to be hci0, which is the sort of answer that is right by accident on a
// single-adapter host and wrong on every other one.
func hciAdapterState(root, name, address string) string {
	if address == "" {
		return "unknown"
	}
	if strings.ToUpper(address) == "00:00:00:00:00:00" {
		return "no address"
	}
	dir := filepath.Join(root, name)
	if _, err := os.Stat(dir); err != nil {
		return "unknown"
	}
	if state := readSysfsAttribute(filepath.Join(dir, "state")); state != "" {
		return strings.ToLower(state)
	}
	// No explicit state file: the address was readable, so the adapter is
	// present. Whether it will answer a command is a separate question that only
	// opening the device can settle, and this function must not open it.
	return "present"
}

// readSysfsAttribute reads a one-line sysfs file, returning "" when it is absent.
func readSysfsAttribute(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// sysfsHexAttributeValue renders a raw uevent hex field as four digits.
func sysfsHexAttributeValue(value string) string {
	if parsed, err := strconv.ParseUint(value, 16, 32); err == nil {
		return fmt.Sprintf("%04x", parsed)
	}
	return value
}

// sysfsHexAttribute reads a sysfs id file and renders it as four hex digits.
func sysfsHexAttribute(path string) string {
	value := readSysfsAttribute(path)
	if value == "" {
		return ""
	}
	if parsed, err := strconv.ParseUint(value, 16, 32); err == nil {
		return fmt.Sprintf("%04x", parsed)
	}
	return value
}

// sysfsUEVENTValue pulls one field out of a uevent file's KEY=VALUE lines.
func sysfsUEVENTValue(uevent, key string) string {
	for _, line := range strings.Split(uevent, "\n") {
		if value, found := strings.CutPrefix(strings.TrimSpace(line), key+"="); found {
			return value
		}
	}
	return ""
}

// ScanBLE passively collects LE advertising reports from an already powered HCI
// adapter for the life of the context.
//
// It enables scanning on the adapter it is given and does nothing else: it never
// connects to a device, never initiates pairing, and never changes power state
// beyond the scanning that was asked for. Reports are delivered as they arrive
// so a caller can stream them.
func (b *LinuxBackend) ScanBLE(ctx context.Context, adapter string, visit func(models.BluetoothDeviceObservation) error) (BLEScanStats, error) {
	stats := BLEScanStats{}
	if adapter == "" {
		adapter = "hci0"
	}
	if visit == nil {
		return stats, fmt.Errorf("BLE observation callback is required")
	}
	index, err := parseHCIIndex(adapter)
	if err != nil {
		return stats, err
	}
	fd, err := unix.Socket(unix.AF_BLUETOOTH, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.BTPROTO_HCI)
	if err != nil {
		return stats, fmt.Errorf("open HCI socket (CAP_NET_RAW may be required): %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrHCI{Dev: uint16(index), Channel: unix.HCI_CHANNEL_RAW}); err != nil {
		return stats, fmt.Errorf("bind HCI adapter %s: %w", adapter, err)
	}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 200000}); err != nil {
		return stats, fmt.Errorf("set HCI receive timeout: %w", err)
	}
	// Enable LE scanning with duplicate filtering left off, so a device that
	// advertises repeatedly is seen as it appears rather than only once.
	if _, err := sendHCICommandForData(fd, ctx, hciOGFLEControl, hciOCFLESetScanEnable, []byte{0x01, 0x00}); err != nil {
		return stats, fmt.Errorf("enable LE scanning on %s: %w", adapter, err)
	}
	defer func() {
		// Scanning is left off again so the adapter is not left listening for
		// the rest of the session after a caller stops asking for reports.
		disableCtx, cancel := context.WithTimeout(context.Background(), leScanDefaultTimeout)
		defer cancel()
		_, _ = sendHCICommandForData(fd, disableCtx, hciOGFLEControl, hciOCFLESetScanEnable, []byte{0x00, 0x00})
	}()

	buffer := make([]byte, 4096)
	for {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		received, err := readHCIPacket(fd, buffer)
		if err != nil {
			if isRetryableSocketError(err) {
				continue
			}
			return stats, fmt.Errorf("read LE advertising report: %w", err)
		}
		observations, err := bluetooth.ParseLEAdvertisingReports(received)
		if err != nil {
			// A report Mansa cannot decode is counted, not fatal: one unknown
			// advertisement must not end a scan that is otherwise working.
			stats.Malformed++
			continue
		}
		for _, observation := range observations {
			if err := visit(observation); err != nil {
				return stats, err
			}
			stats.Reports++
		}
	}
}
