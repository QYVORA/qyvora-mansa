//go:build linux

package transport

import (
	"errors"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// errFilterNotEnabled reports a capture that needs no kernel filter.
var errFilterNotEnabled = errors.New("capture prefilter is not enabled")

// etherProtocolAll is ETH_P_ALL, the protocol both capture sockets use.
const etherProtocolAll = 0x0003

// filterAttachOption and filterDetachOption are the SOL_SOCKET options that
// install and remove a classic BPF program.
const (
	filterAttachOption = unix.SO_ATTACH_FILTER
	filterDetachOption = unix.SO_DETACH_FILTER
)

// attachPrefilter installs a compiled classic BPF program on a packet socket.
// A disabled spec installs nothing. Attaching before the socket is bound means
// frames are discarded in the kernel instead of reaching userspace.
func attachPrefilter(fd int, program []FilterInstruction) error {
	if len(program) == 0 {
		return errFilterNotEnabled
	}
	native := make([]unix.SockFilter, len(program))
	for i, instruction := range program {
		native[i] = unix.SockFilter{Code: instruction.Code, Jt: instruction.JT, Jf: instruction.JF, K: instruction.K}
	}
	// A copy is required because SockFprog holds a pointer to the slice.
	held := make([]unix.SockFilter, len(native))
	copy(held, native)
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, filterAttachOption, &unix.SockFprog{Len: uint16(len(held)), Filter: &held[0]}); err != nil {
		return fmt.Errorf("attach kernel prefilter: %w", err)
	}
	return nil
}

// detachPrefilter removes any installed program. It reports whether a filter
// had been attached so a caller can avoid detaching a socket that never filtered.
func detachPrefilter(fd int) error {
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, filterDetachOption, nil); err != nil {
		return fmt.Errorf("detach kernel prefilter: %w", err)
	}
	return nil
}

// readAttachedPrefilter returns the length of the program the kernel currently
// has attached. The kernel defines SO_GET_FILTER as the same option value as
// SO_ATTACH_FILTER, so reading it back confirms the program was installed rather
// than silently discarded.
func readAttachedPrefilter(fd int) (int, error) {
	var fprog unix.SockFprog
	size := uint32(unsafe.Sizeof(fprog))
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), uintptr(unix.SOL_SOCKET),
		uintptr(filterAttachOption), uintptr(unsafe.Pointer(&fprog)), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return 0, errno
	}
	return int(fprog.Len), nil
}

// probePrefilterSupport opens a short-lived packet socket on the interface,
// attaches the widest assessment program, and removes it again. It never binds,
// so it observes no frames and leaves no filter behind.
func probePrefilterSupport(iface string, linkType uint32) (bool, string) {
	if _, err := net.InterfaceByName(iface); err != nil {
		return false, fmt.Sprintf("interface %q is unavailable: %v", iface, err)
	}
	// A filter is a property of the socket, so the probe never binds and never
	// observes a frame.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(etherProtocolAll)))
	if err != nil {
		return false, fmt.Sprintf("packet socket unavailable (CAP_NET_RAW may be required): %v", err)
	}
	defer unix.Close(fd)
	program, err := CompilePrefilter(linkType, PrefilterSpec{Mode: PrefilterAssessment})
	if err != nil {
		return false, err.Error()
	}
	if len(program) == 0 {
		return false, "the assessment prefilter compiled to no program"
	}
	if err := attachPrefilter(fd, program); err != nil {
		return false, err.Error()
	}
	// Confirm the kernel kept the program and then release it.
	attached, err := readAttachedPrefilter(fd)
	if err != nil {
		_ = detachPrefilter(fd)
		return false, fmt.Sprintf("kernel did not retain the prefilter: %v", err)
	}
	if attached != len(program) {
		_ = detachPrefilter(fd)
		return false, fmt.Sprintf("kernel reported %d prefilter instructions, expected %d", attached, len(program))
	}
	if err := detachPrefilter(fd); err != nil {
		return false, err.Error()
	}
	return true, fmt.Sprintf("attached, read back, and removed a %d instruction kernel prefilter", len(program))
}
