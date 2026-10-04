package wireless

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	pcapGlobalHeaderSize   = 24
	pcapRecordHeaderSize   = 16
	maxCapturePacketSize   = 16 << 20
	maxCaptureAccessPoints = 1 << 16
	linkTypeIEEE80211      = 105
	linkTypeRadiotap       = 127
)

var (
	ErrUnsupportedPCAP = errors.New("unsupported PCAP format")
	ErrMalformedPCAP   = errors.New("malformed PCAP file")
	ErrUnsupportedLink = errors.New("unsupported PCAP link type")
	ErrCaptureLimit    = errors.New("capture exceeds supported topology limit")
)

// PacketRecord describes one classic-PCAP packet. Data aliases an internal
// reusable buffer and is valid only until the callback returns. It begins at
// the 802.11 frame-control field, with a radiotap header removed when present.
type PacketRecord struct {
	Timestamp      time.Time
	CapturedLength uint32
	OriginalLength uint32
	Data           []byte
	Frame          FrameInfo
	FrameError     error
}

// CaptureSummary contains aggregate counts from one streamed PCAP file.
type CaptureSummary struct {
	LinkType                uint32
	SnapLength              uint32
	Interfaces              uint32
	Packets                 uint64
	Malformed               uint64
	FirstPacketAt           time.Time
	LastPacketAt            time.Time
	HandshakeMessages       uint64
	FourWayMessageSets      uint64
	PMKIDObservations       uint64
	MalformedAuthentication uint64
	WEPEncryptedFrames      uint64
	WEPUniqueIVs            uint64
	WEPDuplicateIVs         uint64
	WEPIVTrackingTruncated  bool
}

// ReadPCAP streams a classic PCAP file and invokes visit once for every
// complete packet record. Only raw 802.11 and radiotap link types are accepted.
// Packet payload memory is bounded by maxCapturePacketSize and reused.
func ReadPCAP(r io.Reader, visit func(PacketRecord) error) (CaptureSummary, error) {
	var summary CaptureSummary
	var global [pcapGlobalHeaderSize]byte
	if _, err := io.ReadFull(r, global[:]); err != nil {
		return summary, fmt.Errorf("reading PCAP global header: %w", err)
	}
	order, nanos, err := pcapByteOrder(global[:4])
	if err != nil {
		return summary, err
	}
	major, minor := order.Uint16(global[4:6]), order.Uint16(global[6:8])
	if major != 2 || minor != 4 {
		return summary, fmt.Errorf("%w: version %d.%d", ErrUnsupportedPCAP, major, minor)
	}
	summary.SnapLength = order.Uint32(global[16:20])
	summary.LinkType = order.Uint32(global[20:24]) & 0x0000ffff
	if summary.SnapLength == 0 || summary.SnapLength > maxCapturePacketSize {
		return summary, fmt.Errorf("%w: snap length %d outside supported range", ErrMalformedPCAP, summary.SnapLength)
	}
	if summary.LinkType != linkTypeIEEE80211 && summary.LinkType != linkTypeRadiotap {
		return summary, fmt.Errorf("%w: %d", ErrUnsupportedLink, summary.LinkType)
	}
	packetBuffer := make([]byte, summary.SnapLength)
	var recordHeader [pcapRecordHeaderSize]byte
	for {
		_, err := io.ReadFull(r, recordHeader[:])
		if errors.Is(err, io.EOF) {
			return summary, nil
		}
		if err != nil {
			return summary, fmt.Errorf("%w: packet %d header: %v", ErrMalformedPCAP, summary.Packets+1, err)
		}
		seconds := order.Uint32(recordHeader[0:4])
		fraction := order.Uint32(recordHeader[4:8])
		captured := order.Uint32(recordHeader[8:12])
		original := order.Uint32(recordHeader[12:16])
		fractionLimit := uint32(1_000_000)
		fractionScale := int64(1_000)
		if nanos {
			fractionLimit, fractionScale = 1_000_000_000, 1
		}
		if fraction >= fractionLimit || captured > summary.SnapLength || original < captured {
			return summary, fmt.Errorf("%w: invalid lengths or timestamp at packet %d", ErrMalformedPCAP, summary.Packets+1)
		}
		payload := packetBuffer[:captured]
		if _, err := io.ReadFull(r, payload); err != nil {
			return summary, fmt.Errorf("%w: packet %d payload: %v", ErrMalformedPCAP, summary.Packets+1, err)
		}
		ts := time.Unix(int64(seconds), int64(fraction)*fractionScale).UTC()
		if err := dispatchCapturePacket(&summary, summary.LinkType, ts, captured, original, payload, visit); err != nil {
			return summary, err
		}
	}
}

// ReadCapture detects and streams classic PCAP or PCAPNG input.
func ReadCapture(r io.Reader, visit func(PacketRecord) error) (CaptureSummary, error) {
	return ReadCaptureContext(context.Background(), r, visit)
}

// ReadCaptureContext is ReadCapture with a context available to the visitor.
// The reader itself checks cancellation when the visitor does; it cannot
// interrupt a blocked underlying Reader.
func ReadCaptureContext(ctx context.Context, r io.Reader, visit func(PacketRecord) error) (CaptureSummary, error) {
	br := bufio.NewReader(r)
	magic, err := br.Peek(4)
	if err != nil {
		return CaptureSummary{}, fmt.Errorf("reading capture signature: %w", err)
	}
	if magic[0] == 0x0a && magic[1] == 0x0d && magic[2] == 0x0d && magic[3] == 0x0a {
		return readPCAPNG(ctx, br, visit)
	}
	return ReadPCAP(br, func(record PacketRecord) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if visit == nil {
			return nil
		}
		return visit(record)
	})
}

func dispatchCapturePacket(summary *CaptureSummary, linkType uint32, ts time.Time, captured, original uint32, payload []byte, visit func(PacketRecord) error) error {
	if summary.Packets == 0 {
		summary.FirstPacketAt = ts
	}
	summary.LastPacketAt = ts
	summary.Packets++
	frameBytes, err := pcapFrameBytes(linkType, payload)
	if err != nil {
		summary.Malformed++
		record := PacketRecord{Timestamp: ts, CapturedLength: captured, OriginalLength: original, FrameError: err}
		if visit != nil {
			if callbackErr := visit(record); callbackErr != nil {
				return fmt.Errorf("visiting packet %d: %w", summary.Packets, callbackErr)
			}
		}
		return nil
	}
	frame, parseErr := ParseFrame(frameBytes)
	if parseErr != nil {
		summary.Malformed++
	}
	record := PacketRecord{
		Timestamp: ts, CapturedLength: captured, OriginalLength: original,
		Data: frameBytes, Frame: frame, FrameError: parseErr,
	}
	if visit != nil {
		if callbackErr := visit(record); callbackErr != nil {
			return fmt.Errorf("visiting packet %d: %w", summary.Packets, callbackErr)
		}
	}
	return nil
}

// ParseCapturePacket parses one packet from a raw 802.11 or radiotap capture
// interface. PacketRecord.Data aliases packet and is valid until the caller
// returns; callers that retain it must copy it.
func ParseCapturePacket(linkType uint32, at time.Time, packet []byte) (PacketRecord, error) {
	if linkType != linkTypeIEEE80211 && linkType != linkTypeRadiotap {
		return PacketRecord{}, fmt.Errorf("%w: %d", ErrUnsupportedLink, linkType)
	}
	if len(packet) > maxCapturePacketSize {
		return PacketRecord{}, fmt.Errorf("%w: packet length %d exceeds limit", ErrMalformedPCAP, len(packet))
	}
	var summary CaptureSummary
	var record PacketRecord
	err := dispatchCapturePacket(&summary, linkType, at, uint32(len(packet)), uint32(len(packet)), packet, func(r PacketRecord) error {
		record = r
		return nil
	})
	return record, err
}

func pcapByteOrder(magic []byte) (binary.ByteOrder, bool, error) {
	if len(magic) != 4 {
		return nil, false, ErrMalformedPCAP
	}
	switch [4]byte{magic[0], magic[1], magic[2], magic[3]} {
	case [4]byte{0xd4, 0xc3, 0xb2, 0xa1}:
		return binary.LittleEndian, false, nil
	case [4]byte{0xa1, 0xb2, 0xc3, 0xd4}:
		return binary.BigEndian, false, nil
	case [4]byte{0x4d, 0x3c, 0xb2, 0xa1}:
		return binary.LittleEndian, true, nil
	case [4]byte{0xa1, 0xb2, 0x3c, 0x4d}:
		return binary.BigEndian, true, nil
	default:
		return nil, false, fmt.Errorf("%w: unknown magic number", ErrUnsupportedPCAP)
	}
}

func pcapFrameBytes(linkType uint32, payload []byte) ([]byte, error) {
	if linkType == linkTypeIEEE80211 {
		return payload, nil
	}
	if len(payload) < 8 || payload[0] != 0 {
		return nil, fmt.Errorf("%w: invalid radiotap header", ErrMalformedPCAP)
	}
	headerLength := int(binary.LittleEndian.Uint16(payload[2:4]))
	if headerLength < 8 || headerLength > len(payload) {
		return nil, fmt.Errorf("%w: radiotap length %d exceeds packet", ErrMalformedPCAP, headerLength)
	}
	return payload[headerLength:], nil
}
