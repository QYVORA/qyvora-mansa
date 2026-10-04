package wireless

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"time"
)

const (
	pcapngSectionHeader  = 0x0a0d0d0a
	pcapngInterface      = 1
	pcapngSimplePacket   = 3
	pcapngEnhancedPacket = 6
	maxCaptureBlockSize  = 16 << 20
)

type pcapngInterfaceInfo struct {
	linkType uint32
	snapLen  uint32
	tickBase uint64
	binary   bool
	offset   int64
}

func readPCAPNG(ctx context.Context, r io.Reader, visit func(PacketRecord) error) (CaptureSummary, error) {
	var summary CaptureSummary
	var order binary.ByteOrder
	var interfaces []pcapngInterfaceInfo
	var blockBuffer []byte
	visitPacket := func(record PacketRecord) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if visit != nil {
			return visit(record)
		}
		return nil
	}
	var header [8]byte
	for {
		_, err := io.ReadFull(r, header[:])
		if errors.Is(err, io.EOF) {
			return summary, nil
		}
		if err != nil {
			return summary, fmt.Errorf("%w: truncated block header: %v", ErrMalformedPCAP, err)
		}
		rawType := binary.BigEndian.Uint32(header[:4])
		if rawType == pcapngSectionHeader {
			var bom [4]byte
			if _, err := io.ReadFull(r, bom[:]); err != nil {
				return summary, fmt.Errorf("%w: truncated section header", ErrMalformedPCAP)
			}
			switch bom {
			case [4]byte{0x1a, 0x2b, 0x3c, 0x4d}:
				order = binary.BigEndian
			case [4]byte{0x4d, 0x3c, 0x2b, 0x1a}:
				order = binary.LittleEndian
			default:
				return summary, fmt.Errorf("%w: invalid byte-order marker", ErrMalformedPCAP)
			}
			block, err := readPCAPNGBlock(r, header[:], bom[:], order, &blockBuffer)
			if err != nil {
				return summary, err
			}
			if len(block) < 28 || order.Uint16(block[12:14]) != 1 || order.Uint16(block[14:16]) != 0 {
				return summary, fmt.Errorf("%w: unsupported section version", ErrUnsupportedPCAP)
			}
			interfaces = nil
			continue
		}
		if order == nil {
			return summary, fmt.Errorf("%w: section header must be first", ErrMalformedPCAP)
		}
		totalLength := order.Uint32(header[4:8])
		block, err := readPCAPNGBlock(r, header[:], nil, order, &blockBuffer)
		if err != nil {
			return summary, err
		}
		if uint32(len(block)) != totalLength {
			return summary, fmt.Errorf("%w: invalid block length", ErrMalformedPCAP)
		}
		blockType := order.Uint32(block[:4])
		switch blockType {
		case pcapngInterface:
			iface, err := parsePCAPNGInterface(block, order)
			if err != nil {
				return summary, err
			}
			interfaces = append(interfaces, iface)
			if summary.Interfaces == 0 {
				summary.LinkType, summary.SnapLength = iface.linkType, iface.snapLen
			}
			summary.Interfaces++
		case pcapngEnhancedPacket:
			if len(block) < 32 {
				return summary, fmt.Errorf("%w: short enhanced packet block", ErrMalformedPCAP)
			}
			ifaceID := order.Uint32(block[8:12])
			if uint64(ifaceID) >= uint64(len(interfaces)) {
				return summary, fmt.Errorf("%w: invalid interface id %d", ErrMalformedPCAP, ifaceID)
			}
			iface := interfaces[ifaceID]
			high, low := order.Uint32(block[12:16]), order.Uint32(block[16:20])
			captured, original := order.Uint32(block[20:24]), order.Uint32(block[24:28])
			start := 28
			if captured > iface.snapLen || original < captured || uint64(start)+uint64(pad4(captured))+4 > uint64(len(block)) {
				return summary, fmt.Errorf("%w: invalid enhanced packet lengths", ErrMalformedPCAP)
			}
			ts, err := pcapngTimestamp(uint64(high)<<32|uint64(low), iface)
			if err != nil {
				return summary, err
			}
			payload := block[start : start+int(captured)]
			if err := dispatchCapturePacket(&summary, iface.linkType, ts, captured, original, payload, visitPacket); err != nil {
				return summary, err
			}
		case pcapngSimplePacket:
			if len(block) < 16 || len(interfaces) == 0 {
				return summary, fmt.Errorf("%w: invalid simple packet block", ErrMalformedPCAP)
			}
			iface := interfaces[0]
			original := order.Uint32(block[8:12])
			captured := original
			if captured > iface.snapLen {
				captured = iface.snapLen
			}
			if uint64(12)+uint64(pad4(captured))+4 > uint64(len(block)) {
				return summary, fmt.Errorf("%w: short simple packet data", ErrMalformedPCAP)
			}
			if err := dispatchCapturePacket(&summary, iface.linkType, time.Time{}, captured, original, block[12:12+int(captured)], visitPacket); err != nil {
				return summary, err
			}
		}
		if err := ctx.Err(); err != nil {
			return summary, err
		}
	}
}

func readPCAPNGBlock(r io.Reader, header, prefix []byte, order binary.ByteOrder, buffer *[]byte) ([]byte, error) {
	totalLength := order.Uint32(header[4:8])
	if totalLength < 12 || totalLength > maxCaptureBlockSize || totalLength%4 != 0 {
		return nil, fmt.Errorf("%w: invalid block size %d", ErrMalformedPCAP, totalLength)
	}
	if cap(*buffer) < int(totalLength) {
		*buffer = make([]byte, int(totalLength))
	} else {
		*buffer = (*buffer)[:int(totalLength)]
	}
	block := *buffer
	copy(block, header)
	position := len(header)
	if len(prefix) > 0 {
		copy(block[position:], prefix)
		position += len(prefix)
	}
	if _, err := io.ReadFull(r, block[position:int(totalLength)]); err != nil {
		return nil, fmt.Errorf("%w: truncated block body: %v", ErrMalformedPCAP, err)
	}
	if order.Uint32(block[len(block)-4:]) != totalLength {
		return nil, fmt.Errorf("%w: block length trailer mismatch", ErrMalformedPCAP)
	}
	return block, nil
}

func parsePCAPNGInterface(block []byte, order binary.ByteOrder) (pcapngInterfaceInfo, error) {
	if len(block) < 20 {
		return pcapngInterfaceInfo{}, fmt.Errorf("%w: short interface block", ErrMalformedPCAP)
	}
	linkType := uint32(order.Uint16(block[8:10]))
	if linkType != linkTypeIEEE80211 && linkType != linkTypeRadiotap {
		return pcapngInterfaceInfo{}, fmt.Errorf("%w: %d", ErrUnsupportedLink, linkType)
	}
	snapLen := order.Uint32(block[12:16])
	if snapLen == 0 {
		snapLen = maxCapturePacketSize
	}
	if snapLen > maxCapturePacketSize {
		return pcapngInterfaceInfo{}, fmt.Errorf("%w: interface snap length %d", ErrMalformedPCAP, snapLen)
	}
	iface := pcapngInterfaceInfo{linkType: linkType, snapLen: snapLen, tickBase: 1_000_000}
	for offset, end := 16, len(block)-4; offset < end; {
		if end-offset < 4 {
			return pcapngInterfaceInfo{}, fmt.Errorf("%w: truncated interface option", ErrMalformedPCAP)
		}
		code, length := order.Uint16(block[offset:offset+2]), int(order.Uint16(block[offset+2:offset+4]))
		offset += 4
		padded := (length + 3) &^ 3
		if padded > end-offset {
			return pcapngInterfaceInfo{}, fmt.Errorf("%w: interface option exceeds block", ErrMalformedPCAP)
		}
		value := block[offset : offset+length]
		offset += padded
		switch code {
		case 0:
			if length != 0 {
				return pcapngInterfaceInfo{}, fmt.Errorf("%w: invalid end-of-options marker", ErrMalformedPCAP)
			}
			offset = end
		case 9: // if_tsresol
			if length != 1 {
				return pcapngInterfaceInfo{}, fmt.Errorf("%w: invalid timestamp resolution", ErrMalformedPCAP)
			}
			resolution := value[0]
			iface.binary = resolution&0x80 != 0
			exponent := resolution & 0x7f
			base := uint64(10)
			if iface.binary {
				base = 2
			}
			denom := uint64(1)
			for i := uint8(0); i < exponent; i++ {
				if denom > math.MaxUint64/base {
					return pcapngInterfaceInfo{}, fmt.Errorf("%w: timestamp resolution is too fine", ErrUnsupportedPCAP)
				}
				denom *= base
			}
			if denom > 1_000_000_000 {
				return pcapngInterfaceInfo{}, fmt.Errorf("%w: timestamp resolution is too fine", ErrUnsupportedPCAP)
			}
			iface.tickBase = denom
		case 14: // if_tsoffset
			if length != 8 {
				return pcapngInterfaceInfo{}, fmt.Errorf("%w: invalid timestamp offset", ErrMalformedPCAP)
			}
			iface.offset = int64(order.Uint64(value))
		}
	}
	return iface, nil
}

func pcapngTimestamp(ticks uint64, iface pcapngInterfaceInfo) (time.Time, error) {
	seconds := ticks / iface.tickBase
	if seconds > math.MaxInt64 {
		return time.Time{}, fmt.Errorf("%w: timestamp out of range", ErrMalformedPCAP)
	}
	sec := int64(seconds)
	if (iface.offset > 0 && sec > math.MaxInt64-iface.offset) || (iface.offset < 0 && sec < math.MinInt64-iface.offset) {
		return time.Time{}, fmt.Errorf("%w: timestamp offset out of range", ErrMalformedPCAP)
	}
	nsec := int64((ticks % iface.tickBase) * 1_000_000_000 / iface.tickBase)
	return time.Unix(sec+iface.offset, nsec).UTC(), nil
}

func pad4(length uint32) uint32 { return (length + 3) &^ 3 }
