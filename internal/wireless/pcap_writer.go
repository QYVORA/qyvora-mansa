package wireless

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

const defaultPCAPSnapLen = 65535

// PCAPWriter writes classic PCAP records with microsecond timestamps.
type PCAPWriter struct {
	w       io.Writer
	snapLen uint32
}

// NewPCAPWriter writes a little-endian classic PCAP header.
func NewPCAPWriter(w io.Writer, linkType uint32) (*PCAPWriter, error) {
	if w == nil {
		return nil, fmt.Errorf("nil PCAP writer")
	}
	var header [24]byte
	binary.LittleEndian.PutUint32(header[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(header[4:6], 2)
	binary.LittleEndian.PutUint16(header[6:8], 4)
	binary.LittleEndian.PutUint32(header[16:20], defaultPCAPSnapLen)
	binary.LittleEndian.PutUint32(header[20:24], linkType)
	if err := writeFull(w, header[:]); err != nil {
		return nil, err
	}
	return &PCAPWriter{w: w, snapLen: defaultPCAPSnapLen}, nil
}

// WritePacket writes one captured packet. The packet is rejected if it exceeds
// the advertised snap length rather than silently producing invalid metadata.
func (p *PCAPWriter) WritePacket(at time.Time, packet []byte) error {
	if uint64(len(packet)) > uint64(p.snapLen) {
		return fmt.Errorf("packet length %d exceeds PCAP snap length %d", len(packet), p.snapLen)
	}
	if at.IsZero() {
		at = time.Now()
	}
	at = at.UTC()
	var record [16]byte
	binary.LittleEndian.PutUint32(record[0:4], uint32(at.Unix()))
	binary.LittleEndian.PutUint32(record[4:8], uint32(at.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(record[8:12], uint32(len(packet)))
	binary.LittleEndian.PutUint32(record[12:16], uint32(len(packet)))
	if err := writeFull(p.w, record[:]); err != nil {
		return err
	}
	return writeFull(p.w, packet)
}

func writeFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
