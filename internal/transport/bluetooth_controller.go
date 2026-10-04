package transport

import (
	"context"
	"errors"
	"fmt"

	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// BluetoothControllerProvider reads controller metadata without changing
// adapter state.
type BluetoothControllerProvider interface {
	ControllerInfo(ctx context.Context, adapter string) (models.BluetoothControllerInfo, error)
}

// ControllerInfo returns a deterministic lab fixture. It exists so the
// capability path is exercised in CI; every field is marked simulated so a
// caller cannot mistake it for a real controller.
func (b *SimBackend) ControllerInfo(_ context.Context, adapter string) (models.BluetoothControllerInfo, error) {
	if adapter == "" {
		return models.BluetoothControllerInfo{}, fmt.Errorf("a Bluetooth adapter name is required")
	}
	return models.BluetoothControllerInfo{
		Adapter:        adapter,
		Address:        "02:00:00:00:00:00",
		HCIVersion:     12,
		HCIVersionName: "5.3",
		LMPVersion:     12,
		LMPVersionName: "5.3",
		Manufacturer:   0x05F,
		CompanyName:    "Nordic Semiconductor",
		LEFeatures: []string{
			"LE Encryption",
			"LE Extended Reject Indication",
			"LE Connection Parameter Request Procedure",
			"LE Extended Advertising",
			"LE 2M PHY",
			"LE Periodic Advertising",
			"LE Extended Feature Set",
			"LE Stable Modulation Index Transmitter",
		},
		LEBufferLength: 251,
		LEPackets:      1,
		Simulated:      true,
	}, nil
}

// ErrGATTEnumerationUnavailable reports that the selected backend cannot perform
// live GATT enumeration. The simulated backend returns this instead of
// fabricating a database, because an enumerated table is a statement about a real
// peer and a fixture must never be presented as one.
var ErrGATTEnumerationUnavailable = errors.New("live GATT enumeration requires a Linux HCI adapter; no simulated enumeration exists")

// EnumerateGATT refuses to run on the simulated backend. The deterministic
// fixture remains available through the offline GATT analysis command, which
// labels its output as simulated.
func (b *SimBackend) EnumerateGATT(_ context.Context, _, _ string, _ GATTEnumerationOptions) (GATTEnumerationStats, error) {
	return GATTEnumerationStats{}, ErrGATTEnumerationUnavailable
}
