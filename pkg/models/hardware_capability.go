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
