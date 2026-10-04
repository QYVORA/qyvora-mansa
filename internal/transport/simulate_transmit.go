package transport

import (
	"context"
	"fmt"
	"strings"

	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// simTransmitLinkType is the link type a simulated 802.11 interface reports.
const simTransmitLinkType = 105

// TransmitLinkType reports the link-layer format the simulation provider
// accepts. It exists so a module can be exercised end to end under --sim
// without the caller having to special case the provider.
func (b *SimBackend) TransmitLinkType(iface string) (uint32, error) {
	if err := requireSimulationInterface(iface); err != nil {
		return 0, err
	}
	return simTransmitLinkType, nil
}

// Transmit counts the frames it was handed and emits nothing.
//
// The counts are a faithful record of what was offered, and they are the whole
// result: no simulation can put a frame on the air, so nothing here may be read
// as evidence that a device received anything. OverAirConfirmed stays false on
// the probe below for the same reason.
func (b *SimBackend) Transmit(ctx context.Context, iface string, frames [][]byte) (TransmitStats, error) {
	if err := requireSimulationInterface(iface); err != nil {
		return TransmitStats{}, err
	}
	stats := TransmitStats{}
	for index, frame := range frames {
		// The context is honoured between frames so a cancelled run stops
		// promptly, but the count reports what was accepted up to that point.
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		if len(frame) == 0 {
			return stats, fmt.Errorf("frame %d is empty", index)
		}
		stats.Frames++
		stats.Bytes += uint64(len(frame))
	}
	return stats, nil
}

// ProbeTransmit reports that the simulation provider accepts every frame, and
// that no frame ever reaches the air.
func (b *SimBackend) ProbeTransmit(iface string) (models.TransmitCapability, error) {
	if err := requireSimulationInterface(iface); err != nil {
		return models.TransmitCapability{}, err
	}
	return models.TransmitCapability{
		Interface:        iface,
		Writable:         true,
		WritableReason:   "the simulation provider accepts frames without a socket",
		OverAirConfirmed: false,
	}, nil
}

// requireSimulationInterface accepts the conventional simulation interface name
// and refuses an empty one, so a caller that forgot to name an interface hears
// about it instead of writing to a made-up default.
func requireSimulationInterface(iface string) error {
	trimmed := strings.TrimSpace(iface)
	if trimmed == "" {
		return fmt.Errorf("an interface name is required")
	}
	return nil
}
