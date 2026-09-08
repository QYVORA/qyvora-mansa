package models

import "time"

// WirelessInterface represents a detected network interface.
type WirelessInterface struct {
	Name      string   `json:"name"`
	State     string   `json:"state,omitempty"`
	Mode      string   `json:"mode,omitempty"`
	Supported []string `json:"supported,omitempty"`
}

// AccessPoint is a discovered wireless access point.
type AccessPoint struct {
	BSSID        string                `json:"bssid"`
	SSID         string                `json:"ssid"`
	Channel      int                   `json:"channel"`
	Frequency    int                   `json:"frequency"`
	Band         string                `json:"band"`
	Signal       int                   `json:"signal"`
	Security     SecurityAdvertisement `json:"security"`
	Vendor       string                `json:"vendor,omitempty"`
	Capabilities string                `json:"capabilities,omitempty"`
	FirstSeen    time.Time             `json:"first_seen"`
	LastSeen     time.Time             `json:"last_seen"`
	Source       string                `json:"source,omitempty"`
	IsSimulated  bool                  `json:"is_simulated,omitempty"`
}

// Station is a wireless client associated with an AP.
type Station struct {
	MAC         string   `json:"mac"`
	APBSSID     string   `json:"ap_bssid"`
	Signal      int      `json:"signal,omitempty"`
	ProbedSSIDs []string `json:"probed_ssids,omitempty"`
	Source      string   `json:"source,omitempty"`
}

// SecurityAdvertisement captures the security configuration advertised by an AP.
type SecurityAdvertisement struct {
	Enabled    bool     `json:"enabled"`
	Protocols  []string `json:"protocols,omitempty"`
	Auth       string   `json:"auth,omitempty"`
	Cipher     string   `json:"cipher,omitempty"`
	KeyMgmt    string   `json:"key_mgmt,omitempty"`
	Mode       string   `json:"mode,omitempty"`
	Enterprise bool     `json:"enterprise,omitempty"`
	WPS        bool     `json:"wps,omitempty"`
	RSNIE      string   `json:"rsnie,omitempty"`
}

// WirelessObservation is a single observation of a wireless element.
type WirelessObservation struct {
	ID          string            `json:"id"`
	Key         string            `json:"key"`
	Value       string            `json:"value"`
	Target      string            `json:"target"`
	Source      string            `json:"source"`
	Confidence  Confidence        `json:"confidence"`
	ObservedAt  time.Time         `json:"observed_at"`
	CollectedAt time.Time         `json:"collected_at"`
	Raw         map[string]string `json:"raw,omitempty"`
}

// TrafficObservation captures protocol-level observations.
type TrafficObservation struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	Source     string    `json:"source"`
	Target     string    `json:"target"`
	Protocol   string    `json:"protocol,omitempty"`
	Detail     string    `json:"detail,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}
