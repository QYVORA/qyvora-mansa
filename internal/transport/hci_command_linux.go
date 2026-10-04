//go:build linux

package transport

import (
	"context"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// hciOGFLEControl is the opcode group for LE Controller commands.
const hciOGFLEControl = 0x08

// hciOCFLESetScanEnable is the LE Set Scan Enable command. It is the only
// command in this package that changes controller state, and it is used solely
// to answer a request for live reports; it is switched off again when the scan
// ends.
const hciOCFLESetScanEnable = 0x000c

// hciH4HeaderBytes is the length of the H4 transport header on a command write.
const hciH4HeaderBytes = 3

// parseHCIIndex converts an adapter name into the device index an HCI socket
// binds to. It accepts the plain numeric form only, because a name that merely
// looks like a number would silently address the wrong adapter.
func parseHCIIndex(adapter string) (int, error) {
	name := strings.TrimSpace(adapter)
	if name == "" {
		return 0, fmt.Errorf("a Bluetooth adapter name is required")
	}
	// Both spellings reach this function: sysfs names adapters hci0 and hci1,
	// while some callers hold only the numeric index.
	digits := name
	if rest, found := strings.CutPrefix(name, "hci"); found {
		digits = rest
	}
	index, err := strconv.Atoi(digits)
	if err != nil {
		return 0, fmt.Errorf("adapter %q is not an HCI device index", adapter)
	}
	if index < 0 {
		return 0, fmt.Errorf("adapter index %d is out of range", index)
	}
	return index, nil
}

// sendHCICommandForData writes one HCI command and returns its return
// parameters.
//
// It accepts both completion shapes the controller uses: a Command Complete
// event carrying the parameters, or a Command Status event with a zero status,
// in which case the parameters arrive with the command's own event and this
// function keeps reading. A non-zero status is returned as an error rather than
// being passed off as empty data, because an unread query and an empty answer
// mean different things to a caller building a capability record.
func sendHCICommandForData(fd int, ctx context.Context, ogf, ocf uint16, params []byte) ([]byte, error) {
	opcode := uint16(ogf)<<10 | uint16(ocf)
	if len(params) > 255 {
		return nil, fmt.Errorf("HCI command 0x%04x is too long: %d parameter bytes", opcode, len(params))
	}
	// HCI command packet: type, opcode, parameter length, parameters.
	packet := make([]byte, hciH4HeaderBytes+len(params))
	packet[0] = hciCommandPacket
	binary.LittleEndian.PutUint16(packet[1:3], opcode)
	packet[3] = uint8(len(params))
	copy(packet[hciH4HeaderBytes:], params)
	if err := unix.Sendto(fd, packet, 0, nil); err != nil {
		return nil, fmt.Errorf("send HCI command 0x%04x: %w", opcode, err)
	}

	buffer := make([]byte, 4096)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		received, err := readHCIPacket(fd, buffer)
		if err != nil {
			if isRetryableSocketError(err) {
				// The socket has a receive timeout, so an empty read means the
				// controller has not answered yet rather than that it refused.
				continue
			}
			return nil, fmt.Errorf("read the reply to HCI command 0x%04x: %w", opcode, err)
		}
		if len(received) < 1 || received[0] != hciEventPacket {
			// An ACL packet or a stray event is not this command's answer.
			continue
		}
		switch received[1] {
		case hciEventCommandComplete:
			answerOpcode, status, data, ok := parseCommandComplete(received)
			if !ok || answerOpcode != opcode {
				continue
			}
			if status != 0 {
				return nil, fmt.Errorf("HCI command 0x%04x failed with status 0x%02x", opcode, status)
			}
			return data, nil
		case hciEventCommandStatus:
			answerOpcode, status, ok := parseCommandStatus(received)
			if !ok || answerOpcode != opcode {
				continue
			}
			if status != 0 {
				return nil, fmt.Errorf("HCI command 0x%04x was rejected with status 0x%02x", opcode, status)
			}
			// A zero status means the command was accepted; its result follows in
			// a later event, so keep reading.
		}
	}
}
