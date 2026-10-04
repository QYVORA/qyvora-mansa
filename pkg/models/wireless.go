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
	Hidden       bool                  `json:"hidden,omitempty"`
	FirstSeen    time.Time             `json:"first_seen"`
	LastSeen     time.Time             `json:"last_seen"`
	Source       string                `json:"source,omitempty"`
	IsSimulated  bool                  `json:"is_simulated,omitempty"`
}

// Station is a wireless client and its observed behavior.
type Station struct {
	MAC         string    `json:"mac"`
	APBSSID     string    `json:"ap_bssid"`
	Signal      int       `json:"signal,omitempty"`
	Associated  bool      `json:"associated,omitempty"`
	ProbedSSIDs []string  `json:"probed_ssids,omitempty"`
	FirstSeen   time.Time `json:"first_seen,omitempty"`
	LastSeen    time.Time `json:"last_seen,omitempty"`
	Source      string    `json:"source,omitempty"`
}

// SecurityAdvertisement captures the security configuration advertised by an AP.
type SecurityAdvertisement struct {
	Enabled         bool     `json:"enabled"`
	Protocols       []string `json:"protocols,omitempty"`
	Auth            string   `json:"auth,omitempty"`
	Cipher          string   `json:"cipher,omitempty"`
	KeyMgmt         string   `json:"key_mgmt,omitempty"`
	Mode            string   `json:"mode,omitempty"`
	Enterprise      bool     `json:"enterprise,omitempty"`
	WPS             bool     `json:"wps,omitempty"`
	PMF             bool     `json:"pmf,omitempty"`
	GroupCipher     string   `json:"group_cipher,omitempty"`
	PairwiseCiphers []string `json:"pairwise_ciphers,omitempty"`
	AKMSuites       []string `json:"akm_suites,omitempty"`
	Transition      bool     `json:"transition,omitempty"`
	RSNIE           string   `json:"rsnie,omitempty"`
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
	Count      int       `json:"count,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

// WPAHandshakeObservation captures the fields required to verify a passphrase
// against an observed EAPOL handshake. The cryptographic material is limited to
// what is necessary to perform a local, offline verification.
type WPAHandshakeObservation struct {
	SSID      string `json:"ssid"`
	BSSID     string `json:"bssid"`
	Anonce    []byte `json:"anonce,omitempty"`
	Snonce    []byte `json:"snonce,omitempty"`
	PMKID     []byte `json:"pmkid,omitempty"`
	MIC       []byte `json:"mic,omitempty"`
	EAPOLData []byte `json:"eapol_data,omitempty"`
}

// EAPOLKeyCandidate is a candidate passphrase and its digest. The candidate
// string itself is never persisted by the verification pipeline.
type EAPOLKeyCandidate struct {
	Digest string `json:"digest"`
}

// EAPOLKeyVerification summarizes the outcome of verifying candidates against
// an observed handshake. The passphrase itself is never stored.
type EAPOLKeyVerification struct {
	SSID                string `json:"ssid"`
	BSSID               string `json:"bssid"`
	KDF                 string `json:"kdf"`
	PMKDerivationValid  bool   `json:"pmk_derivation_valid"`
	MICVerification     string `json:"mic_verification"`
	CandidatePassphrase string `json:"-"` // omitted from serialization
	CandidateDigest     string `json:"candidate_digest"`
}
