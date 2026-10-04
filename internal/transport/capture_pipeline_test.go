package transport

import (
	"context"
	"errors"
	"testing"
	"time"
)

type packetFixtureProvider struct {
	packets [][]byte
}

func (packetFixtureProvider) CaptureLinkType(string) (uint32, error) { return 105, nil }

func (p packetFixtureProvider) Capture(_ context.Context, _ string, visit func(time.Time, []byte) error) (CaptureStats, error) {
	stats := CaptureStats{LinkType: 105}
	for i, packet := range p.packets {
		if err := visit(time.Unix(int64(i+1), 0), packet); err != nil {
			return stats, err
		}
		stats.Packets++
		stats.Bytes += uint64(len(packet))
		clear(packet) // Model a provider reusing its receive buffer immediately.
	}
	return stats, nil
}

func TestCaptureQueuedCopiesAndPreservesOrderedPackets(t *testing.T) {
	provider := packetFixtureProvider{packets: [][]byte{{1}, {2}, {3}, {4}}}
	var got []byte
	stats, err := CaptureQueued(context.Background(), provider, "mon0", 1, func(_ time.Time, packet []byte) error {
		got = append(got, packet[0])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string([]byte{1, 2, 3, 4}) {
		t.Fatalf("processed packets = %v, want [1 2 3 4]", got)
	}
	if stats.Packets != 4 || stats.Bytes != 4 {
		t.Fatalf("capture statistics = %+v", stats)
	}
}

func TestCaptureQueuedCancelsProviderWhenProcessingFails(t *testing.T) {
	wantErr := errors.New("disk full")
	provider := packetFixtureProvider{packets: [][]byte{{1}, {2}, {3}}}
	_, err := CaptureQueued(context.Background(), provider, "mon0", 1, func(time.Time, []byte) error {
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want wrapped %v", err, wantErr)
	}
}

func TestCaptureQueuedRejectsInvalidConfiguration(t *testing.T) {
	provider := packetFixtureProvider{}
	for _, size := range []int{0, maxCaptureQueueSize + 1} {
		if _, err := CaptureQueued(context.Background(), provider, "mon0", size, func(time.Time, []byte) error { return nil }); err == nil {
			t.Errorf("queue size %d was accepted", size)
		}
	}
	if _, err := CaptureQueued(context.Background(), provider, "mon0", 1, nil); err == nil {
		t.Fatal("nil processor was accepted")
	}
}
