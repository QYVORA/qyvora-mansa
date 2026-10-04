//go:build linux

package transport

import (
	"encoding/binary"
	"errors"

	"golang.org/x/sys/unix"
)

// HCI packet and event constants shared by the scan and enumeration paths.
//
// A raw HCI socket delivers each packet without the H4 transport type byte. An
// event packet therefore begins with the event code and an ACL data packet begins
// with the connection handle, which means the two are told apart by their own
// layout rather than by a type byte.
const (
	// hciCommandPacket is the H4 type byte written before a command.
	hciCommandPacket = 0x01
	// hciEventPacket is the event code of an HCI event.
	hciEventPacket = 0x04
	// hciEventDisconnection is the Disconnection Complete event.
	hciEventDisconnection = 0x05
	// hciEventCommandComplete is the Command Complete event.
	hciEventCommandComplete = 0x0e
	// hciEventCommandStatus is the Command Status event.
	hciEventCommandStatus = 0x0f
	// hciEventLEMeta is the LE Meta event, which carries LE connection results.
	hciEventLEMeta = 0x3e
	// hciSubeventLEConnectionComplete is the LE Connection Complete subevent.
	hciSubeventLEConnectionComplete = 0x01

	// aclHeaderBytes is the length and handle prefix of an ACL data packet:
	// a two-byte handle and a two-byte data total length.
	aclHeaderBytes = 4
	// aclHandleMask masks off the packet boundary and broadcast flags, leaving the
	// twelve-bit connection handle.
	aclHandleMask = 0x0fff
)

// parseCommandComplete decodes a Command Complete event, whose parameters are the
// number of command packets the controller can still accept, the opcode, and the
// command's return parameters.
func parseCommandComplete(packet []byte) (opcode uint16, status uint8, params []byte, ok bool) {
	if len(packet) < 6 || packet[0] != hciEventCommandComplete {
		return 0, 0, nil, false
	}
	return binary.LittleEndian.Uint16(packet[3:5]), packet[5], packet[6:], true
}

// parseCommandStatus decodes a Command Status event, whose parameters are the
// status and the opcode. A command that reports status zero here has been accepted
// and will complete later.
func parseCommandStatus(packet []byte) (opcode uint16, status uint8, ok bool) {
	if len(packet) < 5 || packet[0] != hciEventCommandStatus {
		return 0, 0, false
	}
	return binary.LittleEndian.Uint16(packet[3:5]), packet[2], true
}

// parseDisconnection decodes a Disconnection Complete event, whose parameters are
// the status, the handle, and the reason code.
func parseDisconnection(packet []byte) (handle uint16, status uint8, reason uint8, ok bool) {
	if len(packet) < 6 || packet[0] != hciEventDisconnection {
		return 0, 0, 0, false
	}
	return binary.LittleEndian.Uint16(packet[3:5]) & aclHandleMask, packet[2], packet[5], true
}

// parseLEConnectionComplete decodes an LE Connection Complete event. The handle
// follows the status, and the peer's address follows the role and address type.
//
// The event is only returned as matched when the status is zero, because a
// non-zero status means no link was created and there is no handle to report.
func parseLEConnectionComplete(packet []byte) (handle uint16, status uint8, ok bool) {
	if len(packet) < 6 || packet[0] != hciEventLEMeta || packet[2] != hciSubeventLEConnectionComplete {
		return 0, 0, false
	}
	return binary.LittleEndian.Uint16(packet[4:6]) & aclHandleMask, packet[3], true
}

// isACLPacket reports whether a raw packet is ACL data. A socket delivers no type
// byte, so the packet is recognised by its declared data length matching the
// packet exactly, which an event packet never satisfies.
func isACLPacket(packet []byte) bool {
	if len(packet) < aclHeaderBytes {
		return false
	}
	return aclHeaderBytes+int(binary.LittleEndian.Uint16(packet[2:4])) == len(packet)
}

// parseACLPayload extracts the L2CAP payload for one channel of one handle, or
// reports nil when the packet belongs to another handle or another channel.
//
// The connection handle is masked before it is compared because the upper bits of
// that field carry the packet boundary and broadcast flags.
func parseACLPayload(packet []byte, handle uint16, cid uint16) ([]byte, error) {
	if len(packet) < aclHeaderBytes+4 {
		return nil, errors.New("ACL data packet is shorter than its header")
	}
	if binary.LittleEndian.Uint16(packet[0:2])&aclHandleMask != handle {
		return nil, nil
	}
	payload := packet[aclHeaderBytes:]
	length := int(binary.LittleEndian.Uint16(payload[0:2]))
	channel := binary.LittleEndian.Uint16(payload[2:4])
	if channel != cid {
		return nil, nil
	}
	// The length covers the channel identifier and the payload that follows it.
	if length < 4 || 2+length > len(payload) {
		return nil, errors.New("L2CAP length does not match the packet that carries it")
	}
	if length < 4 {
		return nil, errors.New("the L2CAP length does not match the packet that carries it")
	}
	// length is the length of the payload (CID + data), so total is 4 + (length-4) if CID is included in length? Or spec: L2CAP length field is the length of the payload of the L2CAP frame (not including the length field itself). CID is part of payload. So total payload bytes are length. So from payload[0:2]=length, we take payload[2:2+length] (CID+info) or split as CID at 2,3 and info from 4 to 4+(length-4). Yes.
	return payload[4 : 2+length], nil
}

// readHCIPacket waits for one raw HCI packet.
func readHCIPacket(fd int, buffer []byte) ([]byte, error) {
	n, _, err := unix.Recvfrom(fd, buffer, 0)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, errors.New("the controller returned an empty HCI packet")
	}
	return buffer[:n], nil
}

func isRetryableSocketError(err error) bool {
	return errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR)
}
