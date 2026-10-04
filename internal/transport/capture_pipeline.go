package transport

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// DefaultCaptureQueueSize bounds packets buffered between the kernel receive
// loop and the single ordered capture consumer.
const DefaultCaptureQueueSize = 256

const maxCaptureQueueSize = 4096
const maxReusablePacketBuffer = 1 << 20

type queuedCapturePacket struct {
	at   time.Time
	data []byte
}

// CaptureQueued separates packet reception from disk and analysis work with a
// bounded queue. It copies callback-owned packet bytes before returning to the
// provider, preserves packet order, applies backpressure instead of dropping
// frames, and cancels the receive loop if the consumer fails.
func CaptureQueued(ctx context.Context, provider CaptureProvider, iface string, queueSize int, process func(time.Time, []byte) error) (CaptureStats, error) {
	return CaptureQueuedWithPrefilter(ctx, provider, iface, queueSize, PrefilterSpec{}, process)
}

// CaptureQueuedWithPrefilter is CaptureQueued with a kernel-side prefilter. When
// the provider cannot install one the capture still runs unfiltered, so a
// missing kernel filter degrades throughput rather than the assessment.
func CaptureQueuedWithPrefilter(ctx context.Context, provider CaptureProvider, iface string, queueSize int, spec PrefilterSpec, process func(time.Time, []byte) error) (CaptureStats, error) {
	if provider == nil {
		return CaptureStats{}, errors.New("capture provider is required")
	}
	if process == nil {
		return CaptureStats{}, errors.New("capture packet processor is required")
	}
	if queueSize < 1 || queueSize > maxCaptureQueueSize {
		return CaptureStats{}, fmt.Errorf("capture queue size must be between 1 and %d", maxCaptureQueueSize)
	}
	if ctx == nil {
		ctx = context.Background()
	}

	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	queue := make(chan queuedCapturePacket, queueSize)
	var buffers sync.Pool
	acquire := func(size int) []byte {
		if value := buffers.Get(); value != nil {
			if data, ok := value.([]byte); ok && cap(data) >= size {
				return data[:size]
			}
		}
		return make([]byte, size)
	}
	release := func(data []byte) {
		if cap(data) <= maxReusablePacketBuffer {
			buffers.Put(data[:0])
		}
	}

	workerDone := make(chan error, 1)
	go func() {
		var processErr error
		for packet := range queue {
			if processErr == nil {
				if err := process(packet.at, packet.data); err != nil {
					processErr = err
					cancel()
				}
			}
			release(packet.data)
		}
		workerDone <- processErr
	}()

	capture := func(ctx context.Context, visit func(time.Time, []byte) error) (CaptureStats, error) {
		if filtered, ok := provider.(PrefilterCaptureProvider); ok && spec.Enabled() {
			return filtered.CaptureWithPrefilter(ctx, iface, spec, visit)
		}
		return provider.Capture(ctx, iface, visit)
	}
	stats, captureErr := capture(workerCtx, func(at time.Time, packet []byte) error {
		data := acquire(len(packet))
		copy(data, packet)
		queued := queuedCapturePacket{at: at, data: data}
		select {
		case queue <- queued:
			return nil
		case <-workerCtx.Done():
			release(data)
			return workerCtx.Err()
		}
	})
	close(queue)
	processErr := <-workerDone
	if processErr != nil {
		return stats, fmt.Errorf("process captured packet: %w", processErr)
	}
	if captureErr != nil {
		return stats, captureErr
	}
	if err := ctx.Err(); err != nil {
		return stats, err
	}
	return stats, nil
}
