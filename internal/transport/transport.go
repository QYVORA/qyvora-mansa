// Package transport defines the Backend interface for wireless data sources
// and provides platform-specific implementations.
package transport

import (
	"context"

	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// Backend is the abstract interface every wireless data source implements.
type Backend interface {
	Name() string
	DiscoverInterfaces() ([]models.WirelessInterface, error)
	Scan(ctx context.Context, iface string, timeout int) ([]models.AccessPoint, []models.Station, error)
	Supported() bool
	Capabilities() []string
}
