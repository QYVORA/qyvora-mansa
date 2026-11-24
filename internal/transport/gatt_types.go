package transport

import (
	"context"
	"time"

	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// GATTEnumerationProvider enumerates a peer's GATT table.
type GATTEnumerationProvider interface {
	EnumerateGATT(ctx context.Context, adapter, address string, options GATTEnumerationOptions) (GATTEnumerationStats, error)
}

// GATTEnumerationOptions bounds one live enumeration.
type GATTEnumerationOptions struct {
	// Timeout bounds the whole enumeration.
	Timeout time.Duration
	// MTU is the ATT receive buffer requested from the peer.
	MTU uint16
	// DiscoverDescriptors requests descriptor discovery in addition to services
	// and characteristics.
	DiscoverDescriptors bool
	// MaxServices, MaxCharacteristics, and MaxDescriptors override the package
	// bounds when lower, so a caller can cap a walk further.
	MaxServices        int
	MaxCharacteristics int
	MaxDescriptors     int
}

// GATTEnumerationStats reports what one enumeration observed.
type GATTEnumerationStats struct {
	Address         string                          `json:"address"`
	Services        int                             `json:"services"`
	Characteristics int                             `json:"characteristics"`
	Descriptors     int                             `json:"descriptors"`
	Requests        int                             `json:"requests"`
	MTU             uint16                          `json:"att_mtu"`
	Truncated       bool                            `json:"truncated"`
	Database        models.GATTDatabase             `json:"database"`
	Controller      *models.BluetoothControllerInfo `json:"controller,omitempty"`
}
