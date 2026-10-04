//go:build linux

package transport

import (
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os/exec"
	"strings"
	"sync"
)

// MonitorLease owns only the temporary monitor interface created by Mansa.
// Closing it removes that interface and never mutates its parent interface.
type MonitorLease struct {
	Name     string
	once     sync.Once
	closeErr error
}

func CreateMonitorInterface(ctx context.Context, parent, name string) (*MonitorLease, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateMonitorName(parent, name); err != nil {
		return nil, err
	}
	if _, err := net.InterfaceByName(parent); err != nil {
		return nil, fmt.Errorf("find parent interface %q: %w", parent, err)
	}
	if _, err := net.InterfaceByName(name); err == nil {
		return nil, fmt.Errorf("monitor interface %q already exists", name)
	}
	out, err := exec.CommandContext(ctx, "iw", "dev", parent, "interface", "add", name, "type", "monitor").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("create monitor interface %s on %s: %w: %s", name, parent, err, strings.TrimSpace(string(out)))
	}
	lease := &MonitorLease{Name: name}
	if err := setInterfaceUp(name); err != nil {
		cleanupErr := lease.Close()
		if cleanupErr != nil {
			return nil, fmt.Errorf("bring monitor interface up: %w (cleanup failed: %v)", err, cleanupErr)
		}
		return nil, fmt.Errorf("bring monitor interface up: %w", err)
	}
	return lease, nil
}

func validateMonitorName(parent, name string) error {
	if strings.TrimSpace(parent) == "" {
		return fmt.Errorf("parent wireless interface is required")
	}
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("monitor interface name is required")
	}
	if len(name) >= unix.IFNAMSIZ || strings.ContainsAny(name, "/\\\x00") || name == "." || name == ".." {
		return fmt.Errorf("invalid monitor interface name %q", name)
	}
	return nil
}

func setInterfaceUp(name string) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	req, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	if err = unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, req); err != nil {
		return err
	}
	req.SetUint16(req.Uint16() | unix.IFF_UP)
	if err = unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, req); err != nil {
		return err
	}
	return nil
}

// Close removes only the monitor interface acquired by CreateMonitorInterface.
func (l *MonitorLease) Close() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		out, err := exec.Command("iw", "dev", l.Name, "del").CombinedOutput()
		if err != nil {
			l.closeErr = fmt.Errorf("remove temporary monitor interface %s: %w: %s", l.Name, err, strings.TrimSpace(string(out)))
		}
	})
	return l.closeErr
}
