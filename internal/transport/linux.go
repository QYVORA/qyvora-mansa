// Package linux implements wireless backend operations on Linux via `iw`.
// When `iw` is unavailable or the user lacks permissions, capabilities
// degrade honestly.
package transport

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/QYVORA/qyvora-mansa/internal/wireless"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// LinuxBackend talks to the real wireless stack via iw.
type LinuxBackend struct{}

// NewLinux returns a Linux iw-based backend.
func NewLinux() *LinuxBackend { return &LinuxBackend{} }

func (b *LinuxBackend) Name() string    { return "linux-iw" }
func (b *LinuxBackend) Supported() bool { return true }

func (b *LinuxBackend) Capabilities() []string {
	capabilities := []string{"raw_capture", "bluetooth_adapter_discovery"}
	if iwAvailable() {
		capabilities = append(capabilities, "wireless_discovery", "ap_enumeration")
	}
	return capabilities
}

// CaptureLinkType reports the kernel link-layer format for an already
// configured 802.11 capture interface. It never changes interface state.
func (b *LinuxBackend) CaptureLinkType(iface string) (uint32, error) {
	device, err := net.InterfaceByName(iface)
	if err != nil {
		return 0, fmt.Errorf("find interface %q: %w", iface, err)
	}
	return linkTypeForDevice(iface, device)
}

// Capture reads frames passively from an already configured raw 802.11
// interface. It does not enable monitor mode or transmit packets.
func (b *LinuxBackend) Capture(ctx context.Context, iface string, visit func(time.Time, []byte) error) (CaptureStats, error) {
	return b.CaptureWithPrefilter(ctx, iface, PrefilterSpec{}, visit)
}

// CaptureWithPrefilter reads frames passively and asks the kernel to discard
// frames the assessment does not need before they reach this process. A
// disabled spec is identical to Capture. The prefilter never changes interface
// mode and never transmits.
func (b *LinuxBackend) CaptureWithPrefilter(ctx context.Context, iface string, spec PrefilterSpec, visit func(time.Time, []byte) error) (CaptureStats, error) {
	if visit == nil {
		return CaptureStats{}, fmt.Errorf("capture callback is required")
	}
	linkType, err := b.CaptureLinkType(iface)
	if err != nil {
		return CaptureStats{}, err
	}
	filter, err := CompilePrefilter(linkType, spec)
	if err != nil {
		return CaptureStats{}, err
	}
	device, err := net.InterfaceByName(iface)
	if err != nil {
		return CaptureStats{}, fmt.Errorf("find interface %q: %w", iface, err)
	}
	if stats, ringReady, ringErr := captureTPacketV3(ctx, device.Index, linkType, filter, visit); ringReady {
		return stats, ringErr
	}
	protocol := htons(etherProtocolAll)
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, int(protocol))
	if err != nil {
		return CaptureStats{}, fmt.Errorf("open packet socket (CAP_NET_RAW required): %w", err)
	}
	defer syscall.Close(fd)
	if err := attachPrefilter(fd, filter); err != nil {
		return CaptureStats{}, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: protocol, Ifindex: device.Index}); err != nil {
		return CaptureStats{}, fmt.Errorf("bind capture socket to %q: %w", iface, err)
	}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Usec: 200000}); err != nil {
		return CaptureStats{}, fmt.Errorf("configure capture timeout: %w", err)
	}
	stats := CaptureStats{LinkType: linkType}
	buf := make([]byte, 65535)
	for {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		n, _, recvErr := syscall.Recvfrom(fd, buf, 0)
		if recvErr != nil {
			if recvErr == syscall.EAGAIN || recvErr == syscall.EWOULDBLOCK || recvErr == syscall.EINTR {
				continue
			}
			return stats, fmt.Errorf("receive capture frame: %w", recvErr)
		}
		if n == 0 {
			continue
		}
		at := time.Now().UTC()
		if err := visit(at, buf[:n]); err != nil {
			return stats, err
		}
		stats.Packets++
		stats.Bytes += uint64(n)
	}
}

func htons(value uint16) uint16 { return value<<8 | value>>8 }

// DiscoverInterfaces lists wireless interfaces via `iw dev`.
func (b *LinuxBackend) DiscoverInterfaces() ([]models.WirelessInterface, error) {
	return b.discoverInterfaces(context.Background())
}

func (b *LinuxBackend) discoverInterfaces(ctx context.Context) ([]models.WirelessInterface, error) {
	if !iwAvailable() {
		return nil, fmt.Errorf("iw is not available; install wireless-tools for live scanning")
	}
	out, err := exec.CommandContext(ctx, "iw", "dev").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("iw dev failed: %w", err)
	}
	return parseIwDev(string(out)), nil
}

// HardwareReport reports observed interfaces and explicitly unknown
// capabilities that require a dedicated native radio probe.
func (b *LinuxBackend) HardwareReport(ctx context.Context) (models.HardwareReport, error) {
	report := models.HardwareReport{Provider: b.Name(), Interfaces: []models.WirelessInterface{}}
	adapters, adapterErr := b.DiscoverBluetoothAdapters()
	if adapterErr == nil {
		report.BluetoothAdapters = adapters
	}
	if !iwAvailable() {
		report.Capabilities = []models.HardwareCapability{{
			ID: models.HardwareWiFiInterfaceDiscovery, Domain: "wifi",
			Implementation: models.CapabilityUnavailable, Hardware: models.CapabilityUnknown,
			Reason: "the iw executable is not installed",
		}}
		appendRawCaptureUnknown(&report, "wireless interfaces could not be queried without iw")
		appendBluetoothAdapterCapability(&report, adapters, adapterErr)
		// Transmit is implemented, so it stays reported as implemented even with
		// no interface to probe; dropping it here would misdescribe the build.
		appendFrameInjectionUnknown(&report, "", "no wireless interface could be selected without iw")
		appendUnimplementedWireless(&report)
		return report, nil
	}
	ifaces, err := b.discoverInterfaces(ctx)
	if err != nil {
		report.Capabilities = []models.HardwareCapability{{
			ID: models.HardwareWiFiInterfaceDiscovery, Domain: "wifi",
			Implementation: models.CapabilityAvailable, Hardware: models.CapabilityUnknown,
			Reason: err.Error(),
		}, {
			ID: models.HardwareWiFiAPEnumeration, Domain: "wifi",
			Implementation: models.CapabilityAvailable, Hardware: models.CapabilityUnknown,
			Reason: "wireless interfaces could not be queried",
		}}
		appendRawCaptureUnknown(&report, "wireless interfaces could not be queried")
		appendBluetoothAdapterCapability(&report, adapters, adapterErr)
		appendFrameInjectionUnknown(&report, "", "no wireless interface could be selected")
		appendUnimplementedWireless(&report)
		return report, nil
	}
	report.Interfaces = ifaces
	deviceState := models.CapabilityUnavailable
	deviceReason := "no wireless interfaces were reported by iw"
	if len(ifaces) > 0 {
		deviceState, deviceReason = models.CapabilityAvailable, "iw reported one or more wireless interfaces"
	}
	report.Capabilities = append(report.Capabilities, models.HardwareCapability{
		ID: models.HardwareWiFiInterfaceDiscovery, Domain: "wifi",
		Implementation: models.CapabilityAvailable, Hardware: deviceState, Reason: deviceReason,
	})
	if len(ifaces) == 0 {
		report.Capabilities = append(report.Capabilities, models.HardwareCapability{
			ID: models.HardwareWiFiAPEnumeration, Domain: "wifi", Implementation: models.CapabilityAvailable,
			Hardware: models.CapabilityUnavailable, Reason: "no wireless interfaces are currently visible",
		})
	} else {
		for _, iface := range ifaces {
			report.Capabilities = append(report.Capabilities, models.HardwareCapability{
				ID: models.HardwareWiFiAPEnumeration, Domain: "wifi", Implementation: models.CapabilityAvailable,
				Hardware: models.CapabilityUnknown, Interface: iface.Name,
				Reason: "interface discovery succeeded; live scan readiness depends on interface state and permissions",
			})
		}
	}
	var captureInterface string
	var captureLinkType uint32
	var captureReason string
	for _, iface := range ifaces {
		linkType, linkErr := b.CaptureLinkType(iface.Name)
		if linkErr == nil {
			captureInterface, captureLinkType = iface.Name, linkType
			break
		}
		captureReason = linkErr.Error()
	}
	if captureInterface != "" {
		report.Capabilities = append(report.Capabilities, models.HardwareCapability{
			ID: models.HardwareWiFiRawCapture, Domain: "wifi", Implementation: models.CapabilityAvailable,
			Hardware: models.CapabilityAvailable, Interface: captureInterface,
			Reason: fmt.Sprintf("raw 802.11 capture is available (link type %d); CAP_NET_RAW is required", captureLinkType),
		})
		// Prove the kernel accepts a prefilter on this interface rather than
		// reporting an implementation-only capability.
		supported, reason := probePrefilterSupport(captureInterface, captureLinkType)
		report.Capabilities = append(report.Capabilities, models.HardwareCapability{
			ID: models.HardwareWiFiKernelPrefilter, Domain: "wifi", Implementation: models.CapabilityAvailable,
			Hardware: stateOrUnknown(supported), Interface: captureInterface, Reason: reason,
		})

	} else if len(ifaces) == 0 {
		appendRawCaptureUnknown(&report, "no wireless interfaces were reported by iw")
	} else {
		appendRawCaptureUnknown(&report, "requires a preconfigured monitor interface: "+captureReason)
	}
	// Transmit is probed independently of capture: a managed interface that
	// cannot run a capture prefilter can still accept raw writes, so failing the
	// capture probe must not be allowed to hide a working transmit path.
	txInterface := captureInterface
	if txInterface == "" && len(ifaces) > 0 {
		txInterface = ifaces[0].Name
	}
	if txInterface != "" {
		tx, txErr := b.ProbeTransmit(txInterface)
		if txErr != nil {
			appendFrameInjectionUnknown(&report, txInterface, txErr.Error())
		} else {
			appendFrameInjection(&report, txInterface, tx)
		}
	} else {
		appendFrameInjectionUnknown(&report, "", "no wireless interface was available to probe")
	}
	appendBluetoothAdapterCapability(&report, adapters, adapterErr)
	appendUnimplementedWireless(&report)
	return report, nil
}

// stateOrUnknown maps a successful probe to available and a failed probe to
// unknown, because a refusal does not distinguish an unsupported kernel from
// missing privileges.
func stateOrUnknown(ok bool) models.CapabilityState {
	if ok {
		return models.CapabilityAvailable
	}
	return models.CapabilityUnknown
}

func appendBluetoothAdapterCapability(report *models.HardwareReport, adapters []models.BluetoothAdapter, err error) {
	hardware := models.CapabilityUnavailable
	reason := "no Bluetooth HCI adapters were reported by sysfs"
	if err != nil {
		hardware, reason = models.CapabilityUnknown, err.Error()
	} else if len(adapters) > 0 {
		hardware, reason = models.CapabilityAvailable, "one or more Bluetooth HCI adapters were reported by sysfs"
	}
	report.Capabilities = append(report.Capabilities, models.HardwareCapability{
		ID: models.HardwareBluetoothAdapterDiscovery, Domain: "bluetooth",
		Implementation: models.CapabilityAvailable, Hardware: hardware, Reason: reason,
	})
}

func appendRawCaptureUnknown(report *models.HardwareReport, reason string) {
	report.Capabilities = append(report.Capabilities, models.HardwareCapability{
		ID: models.HardwareWiFiRawCapture, Domain: "wifi", Implementation: models.CapabilityAvailable,
		Hardware: models.CapabilityUnknown, Reason: reason,
	})
}

// appendFrameInjection reports a probed transmit path. A refused write is
// unavailable rather than unknown: the probe distinguishes a missing permission
// from an unsupported kernel, and both the implementation and the refusal reason
// are known.
func appendFrameInjection(report *models.HardwareReport, iface string, tx models.TransmitCapability) {
	hardware := models.CapabilityAvailable
	reason := fmt.Sprintf("raw frame writes are accepted on %s; %s; over-air delivery is not confirmed by this probe", iface, tx.WritableReason)
	if !tx.Writable {
		hardware = models.CapabilityUnavailable
		reason = tx.WritableReason
	}
	report.Capabilities = append(report.Capabilities, models.HardwareCapability{
		ID: models.HardwareWiFiFrameInjection, Domain: "wifi", Implementation: models.CapabilityAvailable,
		Hardware: hardware, Interface: iface, Reason: reason,
	})
}

func appendFrameInjectionUnknown(report *models.HardwareReport, iface, reason string) {
	report.Capabilities = append(report.Capabilities, models.HardwareCapability{
		ID: models.HardwareWiFiFrameInjection, Domain: "wifi", Implementation: models.CapabilityAvailable,
		Hardware: models.CapabilityUnknown, Interface: iface, Reason: reason,
	})
}

func appendUnimplementedWireless(report *models.HardwareReport) {
	monitorImplementation, monitorReason := models.CapabilityAvailable, "temporary monitor interfaces can be created with iw when the radio/driver supports them; runtime adapter validation is required"
	if !iwAvailable() {
		monitorImplementation, monitorReason = models.CapabilityUnavailable, "iw is not installed; temporary monitor-interface management is unavailable"
	}
	report.Capabilities = append(report.Capabilities, models.HardwareCapability{
		ID: models.HardwareWiFiMonitorMode, Domain: "wifi", Implementation: monitorImplementation,
		Hardware: models.CapabilityUnknown, Reason: monitorReason,
	})
	report.Capabilities = append(report.Capabilities,
		models.HardwareCapability{ID: models.HardwareBLEDiscovery, Domain: "ble", Implementation: models.CapabilityAvailable, Hardware: models.CapabilityUnknown, Reason: "passive HCI LE scanning is implemented; requires an already powered adapter and HCI socket permissions"},
		models.HardwareCapability{ID: models.HardwareBLEGATT, Domain: "ble", Implementation: models.CapabilityAvailable, Hardware: models.CapabilityUnknown, Reason: "offline GATT snapshot analysis is implemented; live GATT enumeration is unavailable"},
	)
	for _, capability := range []struct{ id, domain string }{
		{models.HardwareWiFiClientObservation, "wifi"}, {models.HardwareBluetoothDiscovery, "bluetooth"},
	} {
		report.Capabilities = append(report.Capabilities, models.HardwareCapability{
			ID: capability.id, Domain: capability.domain,
			Implementation: models.CapabilityNotImplemented, Hardware: models.CapabilityUnknown,
			Reason: "Mansa has no provider for this capability yet; hardware support has not been probed",
		})
	}
}

// Scan runs `iw dev <iface> scan` and parses the output.
func (b *LinuxBackend) Scan(_ context.Context, iface string, _ int) ([]models.AccessPoint, []models.Station, error) {
	if !iwAvailable() {
		return nil, nil, fmt.Errorf("iw is not available")
	}
	if iface == "" {
		return nil, nil, fmt.Errorf("no interface specified")
	}
	out, err := exec.Command("iw", "dev", iface, "scan").CombinedOutput()
	if err != nil {
		return nil, nil, fmt.Errorf("iw scan on %s failed: %w\n%s", iface, err, string(out))
	}
	aps := parseIwScan(string(out))
	return aps, nil, nil
}

// Observe reports traffic-level observations. Live capture is not yet
// implemented without monitor mode; the interface degrades honestly.
func (b *LinuxBackend) Observe(_ context.Context, _ string) ([]models.TrafficObservation, error) {
	return nil, nil
}

func iwAvailable() bool {
	_, err := exec.LookPath("iw")
	return err == nil
}

// parseIwDev parses `iw dev` output into interfaces.
func parseIwDev(out string) []models.WirelessInterface {
	var ifaces []models.WirelessInterface
	var current *models.WirelessInterface
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Interface ") {
			if current != nil {
				ifaces = append(ifaces, *current)
			}
			current = &models.WirelessInterface{Name: strings.TrimPrefix(line, "Interface "), State: "unknown"}
		} else if strings.HasPrefix(line, "type ") && current != nil {
			current.Mode = strings.TrimPrefix(line, "type ")
		} else if strings.HasPrefix(line, "state ") && current != nil {
			current.State = strings.TrimPrefix(line, "state ")
		}
	}
	if current != nil {
		ifaces = append(ifaces, *current)
	}
	return ifaces
}

// parseIwScan parses `iw dev <iface> scan` output into access points.
func parseIwScan(out string) []models.AccessPoint {
	var aps []models.AccessPoint
	var current *models.AccessPoint
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "BSS ") {
			if current != nil {
				finalizeAP(current)
				aps = append(aps, *current)
			}
			bssid := strings.TrimPrefix(line, "BSS ")
			if idx := strings.Index(bssid, "("); idx >= 0 {
				bssid = bssid[:idx]
			}
			bssid = strings.TrimSpace(bssid)
			current = &models.AccessPoint{BSSID: bssid}
		} else if current != nil {
			switch {
			case strings.HasPrefix(line, "SSID: "):
				current.SSID = strings.TrimPrefix(line, "SSID: ")
			case strings.HasPrefix(line, "freq: "):
				current.Frequency, _ = strconv.Atoi(strings.TrimPrefix(line, "freq: "))
				ci := models.FreqToChannel(current.Frequency)
				current.Channel = ci.Channel
				current.Band = string(ci.Band)
			case strings.HasPrefix(line, "DS Parameter set: channel "):
				if ch, err := strconv.Atoi(strings.TrimPrefix(line, "DS Parameter set: channel ")); err == nil {
					current.Channel = ch
				}
			case strings.HasPrefix(line, "signal: "):
				sig := strings.TrimPrefix(line, "signal: ")
				sig = strings.TrimSuffix(sig, " dBm")
				current.Signal, _ = strconv.Atoi(sig)
			case strings.HasPrefix(line, "capability: "):
				current.Capabilities = strings.TrimPrefix(line, "capability: ")
				if strings.Contains(current.Capabilities, "Privacy") {
					current.Security.Enabled = true
				}
			case strings.HasPrefix(line, "Group cipher: "):
				current.Security.GroupCipher = strings.TrimPrefix(line, "Group cipher: ")
			case strings.HasPrefix(line, "Pairwise ciphers: "):
				current.Security.PairwiseCiphers = strings.Fields(strings.TrimPrefix(line, "Pairwise ciphers: "))
			case strings.HasPrefix(line, "Authentication suites: "):
				current.Security.AKMSuites = strings.Fields(strings.TrimPrefix(line, "Authentication suites: "))
			case strings.HasPrefix(line, "WPA:") || strings.HasPrefix(line, "RSN:"):
				current.Security.Enabled = true
			case strings.Contains(line, "PMF required") || strings.Contains(line, "PMF capable"):
				current.Security.PMF = true
			}
		}
	}
	if current != nil {
		finalizeAP(current)
		aps = append(aps, *current)
	}
	return aps
}

// finalizeAP derives protocol/cipher fields from the raw RSN data captured
// by iw and normalizes the security advertisement.
func finalizeAP(ap *models.AccessPoint) {
	sec := &ap.Security
	if sec.Enabled && len(sec.AKMSuites) == 0 && sec.GroupCipher == "" {
		return
	}
	var cipher string
	switch {
	case strings.Contains(sec.GroupCipher, "GCMP"):
		cipher = "GCMP"
	case strings.Contains(sec.GroupCipher, "CCMP"):
		cipher = "CCMP"
	case strings.Contains(sec.GroupCipher, "TKIP"):
		cipher = "TKIP"
	}
	var protocols []string
	switch {
	case containsFold(sec.AKMSuites, "SAE"):
		protocols = []string{"WPA3", "SAE"}
	case containsFold(sec.AKMSuites, "OWE"):
		protocols = []string{"OWE"}
	case containsFold(sec.AKMSuites, "802.1X") || containsFold(sec.AKMSuites, "EAP"):
		protocols = []string{"WPA2"}
		sec.Enterprise = true
	default:
		protocols = []string{"WPA2"}
	}
	if cipher != "" {
		protocols = append(protocols, cipher)
	}
	if len(protocols) > 0 {
		sec.Protocols = protocols
		sec.Cipher = cipher
	}
	if len(sec.AKMSuites) > 0 {
		sec.KeyMgmt = strings.Join(sec.AKMSuites, " ")
	}
	wireless.NormalizeSecurity(sec)
}

func containsFold(ss []string, want string) bool {
	for _, s := range ss {
		if strings.EqualFold(strings.TrimSpace(s), want) {
			return true
		}
	}
	return false
}
