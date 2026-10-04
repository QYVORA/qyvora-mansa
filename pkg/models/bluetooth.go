package models

import "time"

// BLEAdvertisement describes an observed BLE advertisement.
type BLEAdvertisement struct {
	Name          string   `json:"name,omitempty"`
	Manufacturer  string   `json:"manufacturer,omitempty"`
	ServiceUUIDs  []string `json:"service_uuids,omitempty"`
	Data          []byte   `json:"data,omitempty"`
	Connectable   bool     `json:"connectable,omitempty"`
	Flags         []byte   `json:"flags,omitempty"`
	Advertisement string   `json:"advertisement,omitempty"`
}

// BluetoothDeviceObservation captures a BLE device seen during scan.
type BluetoothDeviceObservation struct {
	Address       string           `json:"address"`
	AddressType   string           `json:"address_type,omitempty"`
	RSSI          int              `json:"rssi,omitempty"`
	RSSIAvailable bool             `json:"rssi_available,omitempty"`
	Advertisement BLEAdvertisement `json:"advertisement"`
	ScanTimestamp time.Time        `json:"scan_timestamp,omitempty"`
	FirstSeen     time.Time        `json:"first_seen,omitempty"`
	LastSeen      time.Time        `json:"last_seen,omitempty"`
	IsSimulated   bool             `json:"is_simulated,omitempty"`
}
