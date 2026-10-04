package transport

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// etherProtocolAll is ETH_P_ALL, the protocol a packet socket uses to receive
// every frame type.
const etherProtocolAll = 0x0003

// ErrPrefilterUnsupported is returned when a kernel prefilter cannot be used on
// the requested interface.
var ErrPrefilterUnsupported = errors.New("kernel BPF prefilter is not supported for this interface")

// errFilterNotEnabled reports that there was nothing to attach. It is not a
// failure: an unfiltered socket simply receives every frame.
var errFilterNotEnabled = errors.New("no kernel prefilter is installed on this socket")

// linkTypeForDevice reads the ARPHRD value the kernel reports for a network
// interface and converts it into the matching capture link type.
func linkTypeForDevice(iface string, device *net.Interface) (uint32, error) {
	typeBytes, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/type", device.Name))
	if err != nil {
		return 0, fmt.Errorf("read interface type: %w", err)
	}
	linkType, err := strconv.Atoi(strings.TrimSpace(string(typeBytes)))
	if err != nil {
		return 0, fmt.Errorf("parse interface type: %w", err)
	}
	switch linkType {
	case 801: // ARPHRD_IEEE80211
		return linkTypeIEEE80211Capture, nil
	case 803: // ARPHRD_IEEE80211_RADIOTAP
		return linkTypeRadiotapCapture, nil
	default:
		return 0, fmt.Errorf("interface %q is not exposing raw 802.11 frames (kernel type %d)", iface, linkType)
	}
}

// attachPrefilter installs a compiled classic BPF program on a packet socket so
// the kernel discards uninteresting frames before they reach user space. An
// empty program leaves the socket unfiltered.
func attachPrefilter(fd int, filter []FilterInstruction) error {
	if len(filter) == 0 {
		return errFilterNotEnabled
	}
	if len(filter) > maxFilterInstructions {
		return fmt.Errorf("prefilter of %d instructions exceeds the kernel limit of %d", len(filter), maxFilterInstructions)
	}
	program := make([]unix.SockFilter, len(filter))
	for i, instruction := range filter {
		program[i] = unix.SockFilter{
			Code: instruction.Code,
			Jt:   instruction.JT,
			Jf:   instruction.JF,
			K:    instruction.K,
		}
	}
	attached := unix.SockFprog{Len: uint16(len(program)), Filter: &program[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &attached); err != nil {
		return fmt.Errorf("attach kernel prefilter: %w", err)
	}
	return nil
}

// detachPrefilter removes a program installed by attachPrefilter.
func detachPrefilter(fd int) error {
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DETACH_FILTER, 0); err != nil {
		return fmt.Errorf("detach kernel prefilter: %w", err)
	}
	return nil
}

// probePrefilterSupport proves the kernel really accepts a prefilter on the
// given interface instead of reporting an implementation-only capability. It
// attaches an accept-everything program and immediately releases it, so it
// never changes the interface mode and never transmits.
func probePrefilterSupport(iface string, linkType uint32) (bool, string) {
	if runtime.GOOS != "linux" {
		return false, "kernel BPF prefiltering is only available on Linux"
	}
	device, err := net.InterfaceByName(iface)
	if err != nil {
		return false, fmt.Sprintf("find interface %q: %v", iface, err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(etherProtocolAll)))
	if err != nil {
		return false, fmt.Sprintf("open packet socket (CAP_NET_RAW required): %v", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(etherProtocolAll), Ifindex: device.Index}); err != nil {
		return false, fmt.Sprintf("bind packet socket to %q: %v", iface, err)
	}
	if err := attachPrefilter(fd, []FilterInstruction{verdict(bpfAccept)}); err != nil {
		return false, fmt.Sprintf("the kernel refused a prefilter on %q: %v", iface, err)
	}
	if err := detachPrefilter(fd); err != nil {
		return false, fmt.Sprintf("release the probe prefilter on %q: %v", iface, err)
	}
	return true, fmt.Sprintf("the kernel accepted and released a prefilter on %q (link type %d)", iface, linkType)
}

// LinuxPrefilter attaches and releases compiled prefilter programs on an
// already bound packet socket.
type LinuxPrefilter struct{}

// Attach compiles the spec for the socket's link type and installs it. The
// link type is taken from the device the socket is bound to, because the
// offsets in a compiled program depend on it and guessing would silently filter
// the wrong bytes.
func (p *LinuxPrefilter) Attach(fd int, spec PrefilterSpec) error {
	if runtime.GOOS != "linux" {
		return ErrPrefilterUnsupported
	}
	if !spec.Enabled() {
		return nil
	}
	iface, err := unix.GetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	if err != nil || strings.TrimSpace(iface) == "" {
		return fmt.Errorf("%w: the socket is not bound to a named interface", ErrPrefilterUnsupported)
	}
	device, err := net.InterfaceByName(strings.TrimSpace(iface))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPrefilterUnsupported, err)
	}
	linkType, err := linkTypeForDevice(iface, device)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPrefilterUnsupported, err)
	}
	filter, err := CompilePrefilter(linkType, spec)
	if err != nil {
		return err
	}
	return attachPrefilter(fd, filter)
}

// Detach releases the socket's prefilter.
func (p *LinuxPrefilter) Detach(fd int) error {
	return detachPrefilter(fd)
}

// Inspect cannot report the installed filter. The kernel exposes a socket's
// filter only as the compiled program, and x/sys/unix offers no reader for it, so
// there is nothing here that could recover either the original request or
// whether a filter is present. It reports absent rather than guessing.
func (p *LinuxPrefilter) Inspect(fd int) (PrefilterSpec, bool, error) {
	return PrefilterSpec{}, false, nil
}

// Probe reports whether this build can attach a prefilter at all.
func (p *LinuxPrefilter) Probe(fd int) bool {
	return runtime.GOOS == "linux"
}
