// Package simulate provides a deterministic wireless simulation backend.
// No hardware is required; the dataset exercises all analysis rules.
package transport

import (
	"context"
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
		"traffic_observation", "security_analysis", "channel_analysis", "reporting"}
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
			Signal: -55, Security: models.SecurityAdvertisement{Enabled: false, Auth: "OPEN"},
			Vendor: "Ubiquiti", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},
		{BSSID: "02:00:00:00:00:02", SSID: "Airport_WiFi", Channel: 6, Frequency: 2437, Band: "2.4GHz",
			Signal: -48, Security: models.SecurityAdvertisement{Enabled: false, Auth: "OPEN"},
			Vendor: "Cisco", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// WEP network
		{BSSID: "02:00:00:00:00:03", SSID: "LegacyPrinter", Channel: 11, Frequency: 2462, Band: "2.4GHz",
			Signal: -62, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WEP"}},
			Vendor: "Unknown", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// WPA1-TKIP
		{BSSID: "02:00:00:00:00:04", SSID: "OldRouter", Channel: 3, Frequency: 2422, Band: "2.4GHz",
			Signal: -70, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA"}, Cipher: "TKIP", KeyMgmt: "PSK"},
			Vendor: "D-Link", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// WPA2-TKIP (weak, PMF off)
		{BSSID: "02:00:00:00:00:05", SSID: "HomeOffice_WiFi", Channel: 8, Frequency: 2447, Band: "2.4GHz",
			Signal: -45, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA2"}, Cipher: "TKIP", KeyMgmt: "PSK"},
			Vendor: "Netgear", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// WPA2-CCMP (good)
		{BSSID: "02:00:00:00:00:06", SSID: "CorpNet_Secure", Channel: 36, Frequency: 5180, Band: "5GHz",
			Signal: -38, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA2"}, Cipher: "CCMP", KeyMgmt: "PSK", PMF: true},
			Vendor: "Aruba", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// WPA3 (best)
		{BSSID: "02:00:00:00:00:07", SSID: "SmartHome_G5", Channel: 149, Frequency: 5745, Band: "5GHz",
			Signal: -50, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA3", "SAE", "CCMP"}, PMF: true},
			Vendor: "TP-Link", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// WPS enabled, PMF off
		{BSSID: "02:00:00:00:00:08", SSID: "Guest_Net", Channel: 13, Frequency: 2472, Band: "2.4GHz",
			Signal: -58, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA2"}, Cipher: "CCMP", KeyMgmt: "PSK", WPS: true},
			Vendor: "ASUSTeK", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// Hidden SSID open
		{BSSID: "02:00:00:00:00:09", SSID: "", Channel: 6, Frequency: 2437, Band: "2.4GHz",
			Signal: -80, Security: models.SecurityAdvertisement{Enabled: false, Auth: "OPEN"},
			Vendor: "Raspberry Pi", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// Enterprise WPA2-EAP
		{BSSID: "02:00:00:00:00:0A", SSID: "Enterprise_WLAN", Channel: 44, Frequency: 5220, Band: "5GHz",
			Signal: -42, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA2"}, Cipher: "CCMP", KeyMgmt: "EAP", Enterprise: true, PMF: true},
			Vendor: "Cisco", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// 6 GHz WPA3
		{BSSID: "02:00:00:00:00:0B", SSID: "UltraFast_6E", Channel: 9, Frequency: 5995, Band: "6GHz",
			Signal: -35, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA3", "SAE", "CCMP"}, PMF: true},
			Vendor: "Intel", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},
		{BSSID: "02:00:00:00:00:0C", SSID: "6G_Premium", Channel: 37, Frequency: 6135, Band: "6GHz",
			Signal: -40, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA3", "SAE", "GCMP"}, PMF: true},
			Vendor: "Intel", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},
		{BSSID: "02:00:00:00:00:0D", SSID: "Lab_6E", Channel: 61, Frequency: 6255, Band: "6GHz",
			Signal: -47, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA3", "SAE", "CCMP"}, PMF: true},
			Vendor: "Ubiquiti", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},
		{BSSID: "02:00:00:00:00:0E", SSID: "Dev_6GHz", Channel: 85, Frequency: 6375, Band: "6GHz",
			Signal: -52, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA3", "OWE"}, PMF: true},
			Vendor: "Espressif", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},
		{BSSID: "02:00:00:00:00:0F", SSID: "Test_6E", Channel: 113, Frequency: 6515, Band: "6GHz",
			Signal: -55, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA3", "SAE", "CCMP"}, PMF: true},
			Vendor: "Cisco", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// Very strong signal (triggers signal anomaly)
		{BSSID: "02:00:00:00:00:10", SSID: "Nearby_Router", Channel: 1, Frequency: 2412, Band: "2.4GHz",
			Signal: -12, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA2"}, Cipher: "CCMP", KeyMgmt: "PSK", PMF: true},
			Vendor: "D-Link", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// Evil-twin clone of CoffeeShop_Free (open, different transmitter)
		{BSSID: "02:00:00:00:00:11", SSID: "CoffeeShop_Free", Channel: 6, Frequency: 2437, Band: "2.4GHz",
			Signal: -60, Security: models.SecurityAdvertisement{Enabled: false, Auth: "OPEN"},
			Vendor: "Generic", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// Phishing pair: open twin of the secured lounge (same SSID)
		{BSSID: "02:00:00:00:00:12", SSID: "Secured_Lounge", Channel: 100, Frequency: 5500, Band: "5GHz",
			Signal: -46, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA3", "SAE", "CCMP"}, PMF: true},
			Vendor: "Aruba", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},
		{BSSID: "02:00:00:00:00:13", SSID: "Secured_Lounge", Channel: 3, Frequency: 2422, Band: "2.4GHz",
			Signal: -52, Security: models.SecurityAdvertisement{Enabled: false, Auth: "OPEN"},
			Vendor: "Generic", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// Duplicate SSID across bands (legitimate controller, weaker story: PMF on)
		{BSSID: "02:00:00:00:00:14", SSID: "Guest_Net", Channel: 44, Frequency: 5220, Band: "5GHz",
			Signal: -47, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA2"}, Cipher: "CCMP", KeyMgmt: "PSK", PMF: true},
			Vendor: "ASUSTeK", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// Hidden secured network, PMF off
		{BSSID: "02:00:00:00:00:15", SSID: "SecHidden", Channel: 9, Frequency: 2452, Band: "2.4GHz",
			Signal: -70, Hidden: true, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA2"}, Cipher: "CCMP", KeyMgmt: "PSK"},
			Vendor: "D-Link", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// Modern-looking WPA2-CCMP but PMF disabled
		{BSSID: "02:00:00:00:00:16", SSID: "GuestLegacy", Channel: 5, Frequency: 2432, Band: "2.4GHz",
			Signal: -64, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA2"}, Cipher: "CCMP", KeyMgmt: "PSK"},
			Vendor: "TP-Link", FirstSeen: now, LastSeen: now, Source: "simulation", IsSimulated: true},

		// WPA3/WPA2 transition AP allowing downgrade
		{BSSID: "02:00:00:00:00:17", SSID: "Hybrid_Edge", Channel: 40, Frequency: 5200, Band: "5GHz",
			Signal: -68, Security: models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA3", "WPA2"}, Auth: "SAE",
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
