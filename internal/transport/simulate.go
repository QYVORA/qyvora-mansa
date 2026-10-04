// Package simulate provides a deterministic wireless simulation backend.
// No hardware is required; the dataset exercises all analysis rules.
package transport

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/QYVORA/qyvora-mansa/internal/bluetooth"
	"time"

	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// SimBackend is the simulation wireless data source.
type SimBackend struct{}

// New returns a simulation backend.
func New() *SimBackend { return &SimBackend{} }

func (b *SimBackend) Name() string    { return "simulation" }
func (b *SimBackend) Supported() bool { return true }
func (b *SimBackend) Capabilities() []string {
	return []string{"wireless_discovery", "ap_enumeration", "client_observation",
		"traffic_observation", "security_analysis", "channel_analysis", "raw_capture", "ble_discovery", "reporting"}
}

func (b *SimBackend) CaptureLinkType(iface string) (uint32, error) {
	if iface == "" {
		return 0, fmt.Errorf("simulation interface is required")
	}
	return 105, nil
}

// ScanBLE emits deterministic fixture observations through the same callback
// contract as the Linux HCI provider, without opening a socket or radio.
func (b *SimBackend) ScanBLE(ctx context.Context, adapter string, visit func(models.BluetoothDeviceObservation) error) (BLEScanStats, error) {
	if adapter == "" {
		adapter = "hci0"
	}
	if adapter != "hci0" {
		return BLEScanStats{}, fmt.Errorf("simulation has no Bluetooth adapter %q", adapter)
	}
	if visit == nil {
		return BLEScanStats{}, fmt.Errorf("BLE observation callback is required")
	}
	observations, err := bluetooth.ParseLEAdvertisingReports(bluetooth.SimulatedLEAdvertisingReport())
	if err != nil {
		return BLEScanStats{}, fmt.Errorf("parse simulation BLE fixture: %w", err)
	}
	stats := BLEScanStats{}
	for _, observation := range observations {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		if err := visit(observation); err != nil {
			return stats, err
		}
		stats.Reports++
	}
	return stats, nil
}

// Capture emits deterministic beacon and probe-request fixtures immediately.
func (b *SimBackend) Capture(ctx context.Context, iface string, visit func(time.Time, []byte) error) (CaptureStats, error) {
	if _, err := b.CaptureLinkType(iface); err != nil {
		return CaptureStats{}, err
	}
	if visit == nil {
		return CaptureStats{}, fmt.Errorf("capture callback is required")
	}
	frames := [][]byte{simulatedBeaconFrame(), simulatedProbeFrame()}
	stats := CaptureStats{LinkType: 105}
	observedAt := time.Unix(1_700_000_000, 0).UTC()
	for _, frame := range frames {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		if err := visit(observedAt, frame); err != nil {
			return stats, err
		}
		stats.Packets++
		stats.Bytes += uint64(len(frame))
	}
	return stats, nil
}

func simulatedBeaconFrame() []byte {
	frame := make([]byte, 24+12)
	binary.LittleEndian.PutUint16(frame[:2], 8<<4)
	for i := 4; i < 10; i++ {
		frame[i] = 0xff
	}
	copy(frame[10:16], []byte{0x02, 0, 0, 0, 0, 0x10})
	copy(frame[16:22], []byte{0x02, 0, 0, 0, 0, 0x10})
	binary.LittleEndian.PutUint16(frame[32:34], 100)
	frame = append(frame, 0, 9, 'S', 'i', 'm', 'L', 'a', 'b', '-', 'A', 'P', 3, 1, 6)
	return frame
}

func simulatedProbeFrame() []byte {
	frame := make([]byte, 24)
	binary.LittleEndian.PutUint16(frame[:2], 4<<4)
	for i := 4; i < 10; i++ {
		frame[i] = 0xff
	}
	copy(frame[10:16], []byte{0x02, 0, 0, 0, 0, 0x20})
	for i := 16; i < 22; i++ {
		frame[i] = 0xff
	}
	frame = append(frame, 0, 9, 'S', 'i', 'm', 'L', 'a', 'b', '-', 'A', 'P')
	return frame
}

// HardwareReport marks fixture-backed operations as simulated and makes no
// claims about host radios.
func (b *SimBackend) HardwareReport(_ context.Context) (models.HardwareReport, error) {
	interfaces, err := b.DiscoverInterfaces()
	if err != nil {
		return models.HardwareReport{}, err
	}
	report := models.HardwareReport{Provider: b.Name(), Interfaces: interfaces}
	for _, id := range []string{"wifi.interface_discovery", "wifi.ap_enumeration", "wifi.client_observation"} {
		report.Capabilities = append(report.Capabilities, models.HardwareCapability{
			ID: id, Domain: "wifi", Implementation: models.CapabilitySimulated,
			Hardware: models.CapabilityNotApplicable,
			Reason:   "results come from the deterministic simulation fixture",
		})
	}
	report.Capabilities = append(report.Capabilities, models.HardwareCapability{
		ID: "wifi.raw_capture", Domain: "wifi", Implementation: models.CapabilitySimulated,
		Hardware: models.CapabilityNotApplicable, Reason: "deterministic PCAP fixture frames are emitted without radio hardware",
	})
	report.Capabilities = append(report.Capabilities, models.HardwareCapability{
		ID: "wifi.kernel_prefilter", Domain: "wifi", Implementation: models.CapabilitySimulated,
		Hardware: models.CapabilityNotApplicable,
		Reason:   "fixture frames are filtered in process, so no kernel filter is installed",
	})
	for _, id := range []struct{ name, domain string }{
		{"wifi.monitor_mode", "wifi"}, {"wifi.frame_injection", "wifi"},
		{"bluetooth.adapter_discovery", "bluetooth"}, {"bluetooth.discovery", "bluetooth"},
	} {
		report.Capabilities = append(report.Capabilities, models.HardwareCapability{
			ID: id.name, Domain: id.domain, Implementation: models.CapabilityNotImplemented,
			Hardware: models.CapabilityNotApplicable,
			Reason:   "simulation does not emulate this operation",
		})
	}
	for _, id := range []string{"ble.discovery", "ble.gatt"} {
		report.Capabilities = append(report.Capabilities, models.HardwareCapability{ID: id, Domain: "ble", Implementation: models.CapabilitySimulated, Hardware: models.CapabilityNotApplicable, Reason: "deterministic BLE fixture supports offline development without adapter access"})
	}
	return report, nil
}

// DiscoverInterfaces returns simulated wireless interfaces.
func (b *SimBackend) DiscoverInterfaces() ([]models.WirelessInterface, error) {
	return []models.WirelessInterface{
		{Name: "wlan0", State: "up", Mode: "managed", Supported: []string{"2.4GHz", "5GHz", "6GHz"}},
		{Name: "wlan1", State: "down", Mode: "managed", Supported: []string{"2.4GHz", "5GHz"}},
	}, nil
}

// Scan returns a deterministic set of access points and stations.
func (b *SimBackend) Scan(_ context.Context, _ string, _ int) ([]models.AccessPoint, []models.Station, error) {
	now := time.Now().UTC()
	aps := []models.AccessPoint{
		// Open networks
		{BSSID: "02:00:00:00:00:01", SSID: "CoffeeShop_Free", Channel: 1, Frequency: 2412, Band: "2.4GHz",
			Signal: -55, SignalAvailable: true, Security: models.SecurityAdvertisement{Enabled: false, Auth: "OPEN"},
			Vendor: "Ubiquiti", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},
		{BSSID: "02:00:00:00:00:02", SSID: "Airport_WiFi", Channel: 6, Frequency: 2437, Band: "2.4GHz",
			Signal: -48, SignalAvailable: true, Security: models.SecurityAdvertisement{Enabled: false, Auth: "OPEN"},
			Vendor: "Cisco", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// WEP network
		{BSSID: "02:00:00:00:00:03", SSID: "LegacyPrinter", Channel: 11, Frequency: 2462, Band: "2.4GHz",
			Signal: -62, SignalAvailable: true, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WEP"}},
			Vendor: "Unknown", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// WPA1-TKIP
		{BSSID: "02:00:00:00:00:04", SSID: "OldRouter", Channel: 3, Frequency: 2422, Band: "2.4GHz",
			Signal: -70, SignalAvailable: true, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA"}, Cipher: "TKIP", KeyMgmt: "PSK"},
			Vendor: "D-Link", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// WPA2-TKIP (weak, PMF off)
		{BSSID: "02:00:00:00:00:05", SSID: "HomeOffice_WiFi", Channel: 8, Frequency: 2447, Band: "2.4GHz",
			Signal: -45, SignalAvailable: true, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA2"}, Cipher: "TKIP", KeyMgmt: "PSK"},
			Vendor: "Netgear", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// WPA2-CCMP (good)
		{BSSID: "02:00:00:00:00:06", SSID: "CorpNet_Secure", Channel: 36, Frequency: 5180, Band: "5GHz",
			Signal: -38, SignalAvailable: true, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA2"}, Cipher: "CCMP", KeyMgmt: "PSK", PMF: true},
			Vendor: "Aruba", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// WPA3 (best)
		{BSSID: "02:00:00:00:00:07", SSID: "SmartHome_G5", Channel: 149, Frequency: 5745, Band: "5GHz",
			Signal: -50, SignalAvailable: true, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA3", "SAE", "CCMP"}, PMF: true},
			Vendor: "TP-Link", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// WPS enabled, PMF off
		{BSSID: "02:00:00:00:00:08", SSID: "Guest_Net", Channel: 13, Frequency: 2472, Band: "2.4GHz",
			Signal: -58, SignalAvailable: true, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA2"}, Cipher: "CCMP", KeyMgmt: "PSK", WPS: true},
			Vendor: "ASUSTeK", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// Hidden SSID open
		{BSSID: "02:00:00:00:00:09", SSID: "", Channel: 6, Frequency: 2437, Band: "2.4GHz",
			Signal: -80, SignalAvailable: true, Security: models.SecurityAdvertisement{Enabled: false, Auth: "OPEN"},
			Vendor: "Raspberry Pi", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// Enterprise WPA2-EAP
		{BSSID: "02:00:00:00:00:0A", SSID: "Enterprise_WLAN", Channel: 44, Frequency: 5220, Band: "5GHz",
			Signal: -42, SignalAvailable: true, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA2"}, Cipher: "CCMP", KeyMgmt: "EAP", Enterprise: true, PMF: true},
			Vendor: "Cisco", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// 6 GHz WPA3
		{BSSID: "02:00:00:00:00:0B", SSID: "UltraFast_6E", Channel: 9, Frequency: 5995, Band: "6GHz",
			Signal: -35, SignalAvailable: true, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA3", "SAE", "CCMP"}, PMF: true},
			Vendor: "Intel", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},
		{BSSID: "02:00:00:00:00:0C", SSID: "6G_Premium", Channel: 37, Frequency: 6135, Band: "6GHz",
			Signal: -40, SignalAvailable: true, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA3", "SAE", "GCMP"}, PMF: true},
			Vendor: "Intel", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},
		{BSSID: "02:00:00:00:00:0D", SSID: "Lab_6E", Channel: 61, Frequency: 6255, Band: "6GHz",
			Signal: -47, SignalAvailable: true, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA3", "SAE", "CCMP"}, PMF: true},
			Vendor: "Ubiquiti", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},
		{BSSID: "02:00:00:00:00:0E", SSID: "Dev_6GHz", Channel: 85, Frequency: 6375, Band: "6GHz",
			Signal: -52, SignalAvailable: true, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA3", "OWE"}, PMF: true},
			Vendor: "Espressif", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},
		{BSSID: "02:00:00:00:00:0F", SSID: "Test_6E", Channel: 113, Frequency: 6515, Band: "6GHz",
			Signal: -55, SignalAvailable: true, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA3", "SAE", "CCMP"}, PMF: true},
			Vendor: "Cisco", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// Very strong signal (triggers signal anomaly)
		{BSSID: "02:00:00:00:00:10", SSID: "Nearby_Router", Channel: 1, Frequency: 2412, Band: "2.4GHz",
			Signal: -12, SignalAvailable: true, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA2"}, Cipher: "CCMP", KeyMgmt: "PSK", PMF: true},
			Vendor: "D-Link", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// Evil-twin clone of CoffeeShop_Free (open, different transmitter)
		{BSSID: "02:00:00:00:00:11", SSID: "CoffeeShop_Free", Channel: 6, Frequency: 2437, Band: "2.4GHz",
			Signal: -60, SignalAvailable: true, Security: models.SecurityAdvertisement{Enabled: false, Auth: "OPEN"},
			Vendor: "Generic", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// Phishing pair: open twin of the secured lounge (same SSID)
		{BSSID: "02:00:00:00:00:12", SSID: "Secured_Lounge", Channel: 100, Frequency: 5500, Band: "5GHz",
			Signal: -46, SignalAvailable: true, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA3", "SAE", "CCMP"}, PMF: true},
			Vendor: "Aruba", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},
		{BSSID: "02:00:00:00:00:13", SSID: "Secured_Lounge", Channel: 3, Frequency: 2422, Band: "2.4GHz",
			Signal: -52, SignalAvailable: true, Security: models.SecurityAdvertisement{Enabled: false, Auth: "OPEN"},
			Vendor: "Generic", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// Duplicate SSID across bands (legitimate controller, weaker story: PMF on)
		{BSSID: "02:00:00:00:00:14", SSID: "Guest_Net", Channel: 44, Frequency: 5220, Band: "5GHz",
			Signal: -47, SignalAvailable: true, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA2"}, Cipher: "CCMP", KeyMgmt: "PSK", PMF: true},
			Vendor: "ASUSTeK", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// Hidden secured network, PMF off
		{BSSID: "02:00:00:00:00:15", SSID: "SecHidden", Channel: 9, Frequency: 2452, Band: "2.4GHz",
			Signal: -70, Hidden: true, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA2"}, Cipher: "CCMP", KeyMgmt: "PSK"},
			Vendor: "D-Link", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// Modern-looking WPA2-CCMP but PMF disabled
		{BSSID: "02:00:00:00:00:16", SSID: "GuestLegacy", Channel: 5, Frequency: 2432, Band: "2.4GHz",
			Signal: -64, SignalAvailable: true, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA2"}, Cipher: "CCMP", KeyMgmt: "PSK"},
			Vendor: "TP-Link", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// WPA3/WPA2 transition AP allowing downgrade
		{BSSID: "02:00:00:00:00:17", SSID: "Hybrid_Edge", Channel: 40, Frequency: 5200, Band: "5GHz",
			Signal: -68, SignalAvailable: true, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA3", "WPA2"}, Auth: "SAE",
				KeyMgmt: "PSK", AKMSuites: []string{"SAE", "PSK"}, Transition: true},
			Vendor: "Ubiquiti", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},
	}

	stations := []models.Station{
		{MAC: "AA:BB:CC:DD:EE:01", APBSSID: "02:00:00:00:00:06", Signal: -40, Associated: true, FirstSeen: now, LastSeen: now, Source: "simulation"},
		{MAC: "AA:BB:CC:DD:EE:02", APBSSID: "02:00:00:00:00:07", Signal: -48, Associated: true, FirstSeen: now, LastSeen: now, Source: "simulation"},
		{MAC: "AA:BB:CC:DD:EE:03", APBSSID: "02:00:00:00:00:01", Signal: -55, Associated: true, ProbedSSIDs: []string{"Free_WiFi", "CoffeeShop_Free"}, FirstSeen: now, LastSeen: now, Source: "simulation"},
		{MAC: "AA:BB:CC:DD:EE:04", APBSSID: "02:00:00:00:00:02", Signal: -52, Associated: true, FirstSeen: now, LastSeen: now, Source: "simulation"},
		{MAC: "AA:BB:CC:DD:EE:05", Signal: -61, ProbedSSIDs: []string{"Starbucks", "McDonalds_WiFi", "Hotel_WiFi", "Train_Net"}, FirstSeen: now, LastSeen: now, Source: "simulation"},
		{MAC: "AA:BB:CC:DD:EE:06", APBSSID: "02:00:00:00:00:11", Signal: -58, Associated: true, FirstSeen: now, LastSeen: now, Source: "simulation"},
		{MAC: "AA:BB:CC:DD:EE:07", APBSSID: "02:00:00:00:00:12", Signal: -44, Associated: true, FirstSeen: now, LastSeen: now, Source: "simulation"},
	}
	return aps, stations, nil
}

// Observe returns simulated traffic-level observations.
func (b *SimBackend) Observe(_ context.Context, _ string) ([]models.TrafficObservation, error) {
	now := time.Now().UTC()
	return []models.TrafficObservation{
		{ID: "sim-traffic-01", Type: "deauth", Target: "02:00:00:00:00:13", Detail: "802.11 deauth burst", Count: 4, ObservedAt: now},
		{ID: "sim-traffic-02", Type: "deauth", Target: "02:00:00:00:00:11", Detail: "802.11 deauth frames", Count: 1, ObservedAt: now},
		{ID: "sim-traffic-03", Type: "data", Protocol: "http", Target: "02:00:00:00:00:01", Detail: "POST /login cleartext", ObservedAt: now},
		{ID: "sim-traffic-04", Type: "data", Protocol: "dns", Target: "02:00:00:00:00:01", Detail: "plaintext DNS queries", ObservedAt: now},
		{ID: "sim-traffic-05", Type: "data", Protocol: "ftp", Target: "02:00:00:00:00:02", Detail: "FTP control channel", ObservedAt: now},
		{ID: "sim-traffic-06", Type: "data", Protocol: "http", Target: "02:00:00:00:00:11", Detail: "GET /login cleartext", ObservedAt: now},
		{ID: "sim-traffic-07", Type: "data", Protocol: "dot11", Target: "02:00:00:00:00:04", Detail: "TKIP-encrypted data frames", ObservedAt: now},
		{ID: "sim-traffic-08", Type: "data", Protocol: "dot11", Target: "02:00:00:00:00:03", Detail: "WEP-encrypted data frames", ObservedAt: now},
	}, nil
}
