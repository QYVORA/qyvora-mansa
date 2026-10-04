package models

// CapabilityState describes implementation or hardware availability without
// conflating the two.
type CapabilityState string

const (
	CapabilityAvailable      CapabilityState = "available"
	CapabilityUnavailable    CapabilityState = "unavailable"
	CapabilityUnknown        CapabilityState = "unknown"
	CapabilityNotImplemented CapabilityState = "not_implemented"
	CapabilitySimulated      CapabilityState = "simulated"
	CapabilityNotApplicable  CapabilityState = "not_applicable"
)

// HardwareCapability reports one framework capability and its observed
// hardware state. Implementation and Hardware intentionally remain separate.
type HardwareCapability struct {
	ID             string          `json:"id"`
	Domain         string          `json:"domain"`
	Implementation CapabilityState `json:"implementation"`
	Hardware       CapabilityState `json:"hardware"`
	Interface      string          `json:"interface,omitempty"`
	Reason         string          `json:"reason,omitempty"`
}

// HardwareReport is a runtime view of interfaces and their capability states.
type HardwareReport struct {
	Provider          string               `json:"provider"`
	Interfaces        []WirelessInterface  `json:"interfaces"`
	BluetoothAdapters []BluetoothAdapter   `json:"bluetooth_adapters,omitempty"`
	Capabilities      []HardwareCapability `json:"capabilities"`
}

// BluetoothAdapter is read-only adapter metadata discovered from the host.
type BluetoothAdapter struct {
	ID        string `json:"id"`
	Address   string `json:"address,omitempty"`
	Type      string `json:"type,omitempty"`
	Driver    string `json:"driver,omitempty"`
	VendorID  string `json:"vendor_id,omitempty"`
	ProductID string `json:"product_id,omitempty"`
	State     string `json:"state"`
}

// TransmitCapability reports whether an interface can accept raw frame writes.
// The two answers are deliberately separate: a kernel that accepts a write
// proves only that the write was queued, never that a frame reached the air or
// that a peer responded.
type TransmitCapability struct {
	Interface        string `json:"interface,omitempty"`
	Writable         bool   `json:"writable"`
	WritableReason   string `json:"writable_reason,omitempty"`
	OverAirConfirmed bool   `json:"over_air_confirmed"`
}

// Hardware capability identifiers.
//
// The capability contract and the provider reports are written by different
// packages and joined by these identifiers, so they are constants rather than
// string literals written independently on each side. A literal on either side
// compiles fine and then silently fails to join, which would leave every
// capability reporting "unknown" for hardware while looking like it had been
// asked.
const (
	HardwareWiFiInterfaceDiscovery = "wifi.interface_discovery"
	HardwareWiFiAPEnumeration      = "wifi.ap_enumeration"
	HardwareWiFiClientObservation  = "wifi.client_observation"
	HardwareWiFiRawCapture         = "wifi.raw_capture"
	HardwareWiFiKernelPrefilter    = "wifi.kernel_prefilter"
	HardwareWiFiFrameInjection     = "wifi.frame_injection"
	HardwareWiFiMonitorMode        = "wifi.monitor_mode"

	HardwareBluetoothAdapterDiscovery = "bluetooth.adapter_discovery"
	HardwareBluetoothDiscovery        = "bluetooth.discovery"

	HardwareBLEDiscovery = "ble.discovery"
	HardwareBLEGATT      = "ble.gatt"
)
