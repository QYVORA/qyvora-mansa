// Package transport defines the Backend interface for wireless data sources
// and provides platform-specific implementations.
package transport

import (
	"context"
	"time"

	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// Backend is the abstract interface every wireless data source implements.
type Backend interface {
	Name() string
	DiscoverInterfaces() ([]models.WirelessInterface, error)
	Scan(ctx context.Context, iface string, timeout int) ([]models.AccessPoint, []models.Station, error)
	Observe(ctx context.Context, iface string) ([]models.TrafficObservation, error)
	Supported() bool
	Capabilities() []string
}

// CapabilityReporter is implemented by providers that can report runtime
// interface and hardware availability separately from code support.
type CapabilityReporter interface {
	HardwareReport(ctx context.Context) (models.HardwareReport, error)
}

// CaptureProvider reads frames from an already configured capture interface.
// Implementations must be passive and must not change interface mode.
type CaptureProvider interface {
	CaptureLinkType(iface string) (uint32, error)
	Capture(ctx context.Context, iface string, visit func(time.Time, []byte) error) (CaptureStats, error)
}

// PrefilterCaptureProvider is implemented by capture providers that can install
// a kernel-side prefilter. It is optional: a caller must fall back to
// CaptureProvider.Capture when a provider does not implement it.
type PrefilterCaptureProvider interface {
	CaptureWithPrefilter(ctx context.Context, iface string, spec PrefilterSpec, visit func(time.Time, []byte) error) (CaptureStats, error)
}

// BluetoothAdapterProvider performs read-only local HCI adapter discovery.
type BluetoothAdapterProvider interface {
	DiscoverBluetoothAdapters() ([]models.BluetoothAdapter, error)
}

// TransmitProvider sends raw link-layer frames on an already configured
// interface. Implementations must not change interface mode, channel, or
// association state: they transmit and nothing else.
//
// This is the only interface in Mansa that emits radio traffic, so it is
// deliberately narrow. Callers are responsible for authorization and for
// refusing to send unscoped or broadcast frames.
type TransmitProvider interface {
	// TransmitLinkType reports the kernel link-layer format an interface
	// expects on transmit. Frames handed to Transmit must carry the matching
	// capture header (a radiotap header on a radiotap interface).
	TransmitLinkType(iface string) (uint32, error)
	// Transmit writes frames in order. A frame that the kernel rejects aborts
	// the batch and returns the number of frames accepted before the failure.
	Transmit(ctx context.Context, iface string, frames [][]byte) (TransmitStats, error)
}

// TransmitProbe reports whether an interface can accept raw frame writes
// without changing interface mode, channel, or association state.
type TransmitProbe interface {
	ProbeTransmit(iface string) (models.TransmitCapability, error)
}

// TransmitStats counts frames the kernel accepted.
type TransmitStats struct {
	Frames uint64
	Bytes  uint64
}

// CaptureStats summarizes frames delivered by a provider.
type CaptureStats struct {
	LinkType uint32
	Packets  uint64
	Bytes    uint64
}

// BLEScanProvider passively collects LE advertising reports from an already
// powered adapter. It is separate from BluetoothAdapterProvider because listing
// adapters opens nothing while scanning enables scanning on one.
//
// The visit callback receives reports as they arrive, so a caller can stream a
// long scan rather than buffering it.
type BLEScanProvider interface {
	ScanBLE(ctx context.Context, adapter string, visit func(models.BluetoothDeviceObservation) error) (BLEScanStats, error)
}

// BLEScanStats counts what a BLE scan observed.
//
// Malformed counts reports the provider could not decode. It is reported
// separately rather than folded into Reports so a decode gap is visible instead
// of looking like a quiet radio.
type BLEScanStats struct {
	// Reports is the number of advertising reports delivered to the caller.
	Reports uint64

	// Malformed is the number of reports that arrived but could not be decoded.
	Malformed uint64
}
