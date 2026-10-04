//go:build linux

package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/QYVORA/qyvora-mansa/pkg/models"
	"golang.org/x/sys/unix"
)

// TransmitLinkType reports the kernel link-layer format the interface expects on
// transmit.
//
// It is the same answer capture gives, because a frame written to a raw socket
// must carry the header the interface's driver expects. A module that built
// frames for the capture link type therefore needs no separate knowledge.
func (b *LinuxBackend) TransmitLinkType(iface string) (uint32, error) {
	device, err := net.InterfaceByName(iface)
	if err != nil {
		return 0, fmt.Errorf("find interface %q: %w", iface, err)
	}
	return linkTypeForDevice(iface, device)
}

// ProbeTransmit reports whether the interface can accept raw frame writes.
//
// The probe opens a raw packet socket and closes it again, which is the only way
// to learn whether the process may write at all. It sends nothing, and it changes
// no interface state: mode, channel, and association are left exactly as found.
//
// OverAirConfirmed is always false. This backend has no way to establish that a
// frame left the host, and a probe that implied otherwise would be the most
// damaging kind of wrong.
func (b *LinuxBackend) ProbeTransmit(iface string) (models.TransmitCapability, error) {
	device, err := net.InterfaceByName(iface)
	if err != nil {
		return models.TransmitCapability{Interface: iface, Writable: false,
			WritableReason: fmt.Sprintf("interface %s does not exist", iface)}, nil
	}
	if device.Flags&net.FlagUp == 0 {
		return models.TransmitCapability{Interface: iface, Writable: false,
			WritableReason: fmt.Sprintf("interface %s is down", iface)}, nil
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return models.TransmitCapability{Interface: iface, Writable: false,
			WritableReason: fmt.Sprintf("a raw packet socket could not be opened (CAP_NET_RAW may be required): %v", err)}, nil
	}
	if err := unix.Close(fd); err != nil {
		return models.TransmitCapability{Interface: iface, Writable: false,
			WritableReason: fmt.Sprintf("the raw packet socket could not be closed: %v", err)}, nil
	}
	return models.TransmitCapability{
		Interface:        iface,
		Writable:         true,
		WritableReason:   "a raw packet socket was opened and closed without sending anything",
		OverAirConfirmed: false,
	}, nil
}

// Transmit writes frames to the interface in order.
//
// It changes no interface state: mode, channel, and association are left as
// found. A frame the kernel rejects aborts the batch and the error carries the
// count of frames already accepted, because a caller reporting "sent 10 of 12"
// is describing something different from one reporting "sent nothing".
//
// The returned count is what the kernel queued. It is never evidence that a frame
// reached the air or that anything answered.
func (b *LinuxBackend) Transmit(ctx context.Context, iface string, frames [][]byte) (TransmitStats, error) {
	stats := TransmitStats{}
	if iface == "" {
		return stats, fmt.Errorf("an interface name is required")
	}
	if len(frames) == 0 {
		return stats, fmt.Errorf("no frames to transmit")
	}
	linkType, err := b.TransmitLinkType(iface)
	if err != nil {
		return stats, err
	}
	protocol := uint16(linkType)
	device, err := net.InterfaceByName(iface)
	if err != nil {
		return stats, fmt.Errorf("find interface %q: %w", iface, err)
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return stats, fmt.Errorf("open a raw packet socket (CAP_NET_RAW may be required): %w", err)
	}
	defer unix.Close(fd)

	// Binding the socket to the interface is what scopes the write to it, so a
	// frame cannot go out on a different adapter than the one authorized.
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(protocol),
		Ifindex:  device.Index,
		Halen:    6,
	}); err != nil {
		return stats, fmt.Errorf("bind raw socket to %s: %w", iface, err)
	}

	for index, frame := range frames {
		if err := ctx.Err(); err != nil {
			return stats, fmt.Errorf("stopped after %d accepted frame(s): %w", stats.Frames, err)
		}
		if len(frame) == 0 {
			return stats, fmt.Errorf("frame %d is empty", index)
		}
		if err := unix.Sendto(fd, frame, 0, &unix.SockaddrLinklayer{
			Protocol: htons(protocol),
			Ifindex:  device.Index,
			Halen:    6,
			Addr:     [8]byte{},
		}); err != nil {
			if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENETDOWN) || errors.Is(err, syscall.EPERM) {
				return stats, fmt.Errorf("the kernel rejected frame %d after accepting %d: %w", index, stats.Frames, err)
			}
			return stats, fmt.Errorf("write frame %d after accepting %d: %w", index, stats.Frames, err)
		}
		stats.Frames++
		stats.Bytes += uint64(len(frame))
	}
	return stats, nil
}
