//go:build !linux

package transport

import (
	"context"
	"errors"

	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

var errLinuxOnly = errors.New("Linux wireless operations are unavailable on this platform")

// LinuxBackend is a compile-time placeholder on non-Linux platforms. It reports
// itself unsupported so callers fall back to the simulated backend.
type LinuxBackend struct{}

func NewLinux() *LinuxBackend { return &LinuxBackend{} }

func (b *LinuxBackend) Name() string           { return "linux-iw" }
func (b *LinuxBackend) Supported() bool        { return false }
func (b *LinuxBackend) Capabilities() []string { return nil }
func (b *LinuxBackend) DiscoverInterfaces() ([]models.WirelessInterface, error) {
	return nil, errLinuxOnly
}
func (b *LinuxBackend) Scan(context.Context, string, int) ([]models.AccessPoint, []models.Station, error) {
	return nil, nil, errLinuxOnly
}
func (b *LinuxBackend) Observe(context.Context, string) ([]models.TrafficObservation, error) {
	return nil, errLinuxOnly
}

// MonitorLease is a compile-time placeholder on non-Linux platforms.
type MonitorLease struct{ Name string }

func (l *MonitorLease) Close() error { return errLinuxOnly }

func CreateMonitorInterface(context.Context, string, string) (*MonitorLease, error) {
	return nil, errLinuxOnly
}

// LinuxChannelController is a compile-time placeholder on non-Linux platforms.
type LinuxChannelController struct{ Interface string }

func (c LinuxChannelController) Channels(context.Context) ([]RadioChannel, error) {
	return nil, errLinuxOnly
}
func (c LinuxChannelController) CurrentChannel(context.Context) (RadioChannel, error) {
	return RadioChannel{}, errLinuxOnly
}
func (c LinuxChannelController) SetChannel(context.Context, RadioChannel) error {
	return errLinuxOnly
}
