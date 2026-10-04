//go:build linux

package transport

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	packetVersionOption = 10
	ringBlockSize       = 1 << 20
	ringBlockCount      = 4
	ringFrameSize       = 2048
	ringPollMillis      = 200
)

// captureTPacketV3 uses Linux's block-oriented PACKET_MMAP receive ring. The
// callback's packet bytes are borrowed from the ring and valid only until it
// returns, matching the CaptureProvider contract used by CaptureQueued.
func captureTPacketV3(ctx context.Context, ifaceIndex int, linkType uint32, filter []FilterInstruction, visit func(time.Time, []byte) error) (CaptureStats, bool, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(etherProtocolAll)))
	if err != nil {
		return CaptureStats{}, false, fmt.Errorf("open packet ring socket: %w", err)
	}
	defer unix.Close(fd)
	if err = unix.SetsockoptInt(fd, unix.SOL_PACKET, packetVersionOption, unix.TPACKET_V3); err != nil {
		return CaptureStats{}, false, nil
	}
	req := unix.TpacketReq3{Block_size: ringBlockSize, Block_nr: ringBlockCount, Frame_size: ringFrameSize, Frame_nr: ringBlockSize / ringFrameSize * ringBlockCount, Retire_blk_tov: 64}
	if err = unix.SetsockoptTpacketReq3(fd, unix.SOL_PACKET, unix.PACKET_RX_RING, &req); err != nil {
		return CaptureStats{}, false, nil
	}
	defer func() {
		zero := unix.TpacketReq3{}
		_ = unix.SetsockoptTpacketReq3(fd, unix.SOL_PACKET, unix.PACKET_RX_RING, &zero)
	}()
	// Filtering before the bind keeps unrelated frames out of the ring entirely.
	if err = attachPrefilter(fd, filter); err != nil && !errors.Is(err, errFilterNotEnabled) {
		return CaptureStats{}, true, err
	}
	if len(filter) > 0 {
		defer func() { _ = detachPrefilter(fd) }()
	}
	if err = unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(etherProtocolAll), Ifindex: ifaceIndex}); err != nil {
		return CaptureStats{}, true, fmt.Errorf("bind packet ring: %w", err)
	}
	area, err := unix.Mmap(fd, 0, ringBlockSize*ringBlockCount, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return CaptureStats{}, true, fmt.Errorf("map packet ring: %w", err)
	}
	defer unix.Munmap(area)
	stats := CaptureStats{LinkType: linkType}
	for blockIndex := 0; ; blockIndex = (blockIndex + 1) % ringBlockCount {
		if err := ctx.Err(); err != nil {
			return stats, true, err
		}
		block := area[blockIndex*ringBlockSize : (blockIndex+1)*ringBlockSize]
		desc := (*unix.TpacketBlockDesc)(unsafe.Pointer(&block[0]))
		status := (*uint32)(unsafe.Pointer(&desc.Hdr[0]))
		if atomic.LoadUint32(status)&unix.TP_STATUS_USER == 0 {
			fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			_, pollErr := unix.Poll(fds, ringPollMillis)
			if pollErr != nil && pollErr != unix.EINTR {
				return stats, true, fmt.Errorf("wait for packet ring: %w", pollErr)
			}
			continue
		}
		hdr := (*unix.TpacketHdrV1)(unsafe.Pointer(&desc.Hdr[0]))
		if err := visitRingBlock(block, hdr, func(at time.Time, frame []byte) error {
			if err := visit(at, frame); err != nil {
				return err
			}
			stats.Packets++
			stats.Bytes += uint64(len(frame))
			return nil
		}); err != nil {
			atomic.StoreUint32(status, unix.TP_STATUS_KERNEL)
			return stats, true, err
		}
		atomic.StoreUint32(status, unix.TP_STATUS_KERNEL)
	}
}

func visitRingBlock(block []byte, hdr *unix.TpacketHdrV1, visit func(time.Time, []byte) error) error {
	if hdr.Offset_to_first_pkt >= uint32(len(block)) || hdr.Num_pkts > uint32(len(block)/unix.SizeofTpacket3Hdr) {
		return fmt.Errorf("invalid packet ring block metadata")
	}
	offset := int(hdr.Offset_to_first_pkt)
	for i := uint32(0); i < hdr.Num_pkts; i++ {
		if offset < 0 || offset > len(block)-unix.SizeofTpacket3Hdr {
			return fmt.Errorf("packet ring header exceeds block bounds")
		}
		packet := (*unix.Tpacket3Hdr)(unsafe.Pointer(&block[offset]))
		start := offset + int(packet.Mac)
		end := start + int(packet.Snaplen)
		if packet.Mac == 0 || packet.Snaplen == 0 || start < offset || end < start || end > len(block) {
			return fmt.Errorf("packet ring frame exceeds block bounds")
		}
		at := time.Unix(int64(packet.Sec), int64(packet.Nsec)).UTC()
		if err := visit(at, block[start:end]); err != nil {
			return err
		}
		if i+1 < hdr.Num_pkts {
			if packet.Next_offset < unix.SizeofTpacket3Hdr || int(packet.Next_offset) > len(block)-offset {
				return fmt.Errorf("invalid packet ring next-frame offset")
			}
			offset += int(packet.Next_offset)
		}
	}
	return nil
}
