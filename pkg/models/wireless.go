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
	BSSID              string                `json:"bssid"`
	SSID               string                `json:"ssid"`
	Channel            int                   `json:"channel"`
	Frequency          int                   `json:"frequency"`
	Band               string                `json:"band"`
	Signal             int                   `json:"signal"`
	Security           SecurityAdvertisement `json:"security"`
	Vendor             string                `json:"vendor,omitempty"`
	Capabilities       string                `json:"capabilities,omitempty"`
	CapabilityFlags    []string              `json:"capability_flags,omitempty"`
	SupportedRatesMbps []float32             `json:"supported_rates_mbps,omitempty"`
	BasicRatesMbps     []float32             `json:"basic_rates_mbps,omitempty"`
	Hidden             bool                  `json:"hidden,omitempty"`
	FirstSeen          time.Time             `json:"first_seen"`
	LastSeen           time.Time             `json:"last_seen"`
	Source             string                `json:"source,omitempty"`
	IsSimulated        bool                  `json:"is_simulated,omitempty"`
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

// WirelessAuthenticationObservation records protocol metadata extracted from
// an unencrypted 802.11 EAPOL exchange. It never contains a candidate secret.
type WirelessAuthenticationObservation struct {
	BSSID                  string    `json:"bssid"`
	Station                string    `json:"station"`
	Kind                   string    `json:"kind"`
	Message                string    `json:"message,omitempty"`
	FourWaySetComplete     bool      `json:"four_way_message_set_observed,omitempty"`
	ReplayCounter          uint64    `json:"replay_counter,omitempty"`
	DescriptorType         uint8     `json:"descriptor_type,omitempty"`
	PMKIDSHA256            string    `json:"pmkid_sha256,omitempty"`
	WEPEncryptedFrames     uint64    `json:"wep_encrypted_frames,omitempty"`
	WEPUniqueIVs           uint64    `json:"wep_unique_ivs,omitempty"`
	WEPDuplicateIVs        uint64    `json:"wep_duplicate_ivs,omitempty"`
	WEPIVTrackingTruncated bool      `json:"wep_iv_tracking_truncated,omitempty"`
	ObservedAt             time.Time `json:"observed_at"`
	// Verification carries the material needed to check a candidate passphrase
	// against this message. It is populated only for an EAPOL-Key message that
	// carries a message integrity code, and never contains a secret: the ANonce
	// is public and the MIC is a truncated keyed hash.
	Verification *EAPOLKeyVerification `json:"verification,omitempty"`
}

// EAPOLKeyCandidate is one interpretation of an EAPOL-Key message integrity
// code: a MIC length and the code the peer transmitted at that offset.
type EAPOLKeyCandidate struct {
	// MICLength is 8 for the SHA-1 suites and 16 for the SHA-256 suites.
	MICLength int `json:"mic_length"`
	// MIC is the code the peer transmitted, in hexadecimal.
	MIC string `json:"mic"`
}

// EAPOLKeyVerification is the public handshake material required to recompute a
// message integrity code from a candidate pairwise master key. The zero value
// means the observation cannot be used for verification.
type EAPOLKeyVerification struct {
	Message     string `json:"message"`
	KeyInfo     uint16 `json:"key_info"`
	ANonce      string `json:"a_nonce"`
	SNonce      string `json:"s_nonce"`
	SNonceValid bool   `json:"s_nonce_present"`
	// Candidates holds every message integrity code consistent with the captured
	// body. The negotiated cipher suite is not carried in the frame, so a body
	// whose key data length cannot distinguish the SHA-1 and SHA-256 variants
	// yields more than one candidate and a verifier must try each.
	Candidates []EAPOLKeyCandidate `json:"candidates"`
	// KeyIV is the unencrypted initialization vector of the message.
	KeyIV string `json:"key_iv"`
	// ReplayCounter is the replay counter carried by the message.
	ReplayCounter uint64 `json:"replay_counter"`
	// SessionKeyID is the KDE selector of the captured message, empty for a
	// handshake message that carries no KDE.
	SessionKeyID string `json:"session_key_id,omitempty"`
	// PMKID is a PMKID observed in a KDE. A PMKID is itself a master key, so a
	// session carrying one can be verified without a passphrase.
	PMKID string `json:"pmkid,omitempty"`
	// SSID and BSSID identify the network the message belongs to.
	SSID  string `json:"ssid,omitempty"`
	BSSID string `json:"bssid"`
	// CapturedEAPOL is the complete four-byte EAPOL header followed by the key
	// data as transmitted, so the MIC input is reproduced exactly.
	CapturedEAPOL string `json:"captured_eapol"`
}
