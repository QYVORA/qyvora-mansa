package models

// BLEAdvertisement is the normalized subset of a BLE advertising payload
// currently decoded by Mansa.
type BLEAdvertisement struct {
	Name             string            `json:"name"`
	CompleteName     bool              `json:"complete_name,omitempty"`
	TxPower          *int8             `json:"tx_power,omitempty"`
	ServiceUUIDs     []string          `json:"service_uuids,omitempty"`
	ManufacturerData map[uint16][]byte `json:"manufacturer_data,omitempty"`
}

// BluetoothDeviceObservation is one normalized report from a captured HCI LE
// advertising event.
type BluetoothDeviceObservation struct {
	Address        string           `json:"address"`
	AddressType    uint8            `json:"address_type"`
	EventType      uint16           `json:"event_type"`
	RSSI           int8             `json:"rssi"`
	RSSIAvailable  bool             `json:"rssi_available"`
	TxPower        *int8            `json:"tx_power,omitempty"`
	PrimaryPHY     uint8            `json:"primary_phy,omitempty"`
	SecondaryPHY   uint8            `json:"secondary_phy,omitempty"`
	AdvertisingSID uint8            `json:"advertising_sid,omitempty"`
	DataStatus     string           `json:"data_status,omitempty"`
	Advertisement  BLEAdvertisement `json:"advertisement"`
}

// GATTDatabase is a normalized snapshot of one device's discovered GATT
// attribute table. It contains metadata only; characteristic values are not
// captured by this model.
type GATTDatabase struct {
	DeviceAddress string        `json:"device_address"`
	Services      []GATTService `json:"services"`
	Simulated     bool          `json:"simulated,omitempty"`
}

type GATTService struct {
	UUID            string               `json:"uuid"`
	Primary         bool                 `json:"primary"`
	StartHandle     uint16               `json:"start_handle,omitempty"`
	EndHandle       uint16               `json:"end_handle,omitempty"`
	Characteristics []GATTCharacteristic `json:"characteristics,omitempty"`
}

type GATTCharacteristic struct {
	UUID string `json:"uuid"`
	// Handle is the attribute handle of the characteristic value, which is the
	// handle a read or write of the characteristic uses.
	Handle uint16 `json:"handle"`
	// DeclarationHandle is the handle of the 0x2803 attribute that declares the
	// characteristic. It sits immediately before the value attribute and is what
	// bounds the descriptor range that follows the value.
	DeclarationHandle uint16           `json:"declaration_handle"`
	Properties        []GATTProperty   `json:"properties,omitempty"`
	Permissions       GATTPermissions  `json:"permissions"`
	Descriptors       []GATTDescriptor `json:"descriptors,omitempty"`
}

type GATTDescriptor struct {
	UUID   string `json:"uuid"`
	Handle uint16 `json:"handle"`
}

type GATTProperty string

const (
	GATTPropertyRead                 GATTProperty = "read"
	GATTPropertyWrite                GATTProperty = "write"
	GATTPropertyWriteWithoutResponse GATTProperty = "write_without_response"
	GATTPropertyNotify               GATTProperty = "notify"
	GATTPropertyIndicate             GATTProperty = "indicate"
)

// GATTPermissions describes access controls reported by a GATT provider.
// False means no such restriction was reported; it does not prove a remote
// client can access the attribute without pairing or connection policy.
type GATTPermissions struct {
	Read               bool `json:"read,omitempty"`
	Write              bool `json:"write,omitempty"`
	ReadEncrypted      bool `json:"read_encrypted,omitempty"`
	WriteEncrypted     bool `json:"write_encrypted,omitempty"`
	ReadAuthenticated  bool `json:"read_authenticated,omitempty"`
	WriteAuthenticated bool `json:"write_authenticated,omitempty"`
	ReadAuthorized     bool `json:"read_authorized,omitempty"`
	WriteAuthorized    bool `json:"write_authorized,omitempty"`
}

// BluetoothControllerInfo is controller metadata read with read-only HCI
// commands. Every field is a controller statement; none of it is inferred from
// a device seen on the air.
type BluetoothControllerInfo struct {
	Adapter        string `json:"adapter"`
	Address        string `json:"address,omitempty"`
	HCIVersion     uint8  `json:"hci_version"`
	HCIVersionName string `json:"hci_version_name"`
	LMPVersion     uint8  `json:"lmp_version"`
	LMPVersionName string `json:"lmp_version_name,omitempty"`
	Manufacturer   uint16 `json:"manufacturer_id"`
	CompanyName    string `json:"company_name,omitempty"`
	// SupportedCommands is the 64-octet bitmap the controller reports.
	SupportedCommandsHex string `json:"supported_commands,omitempty"`
	// LEFeatures lists the LE feature bits the controller reports as set.
	LEFeatures     []string `json:"le_features,omitempty"`
	LEBufferLength uint8    `json:"le_buffer_length,omitempty"`
	LEPackets      uint8    `json:"le_acl_packets,omitempty"`
	Simulated      bool     `json:"simulated,omitempty"`
	Unreadable     []string `json:"unreadable,omitempty"`
}
