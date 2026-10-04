package lab

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/QYVORA/qyvora-mansa/internal/transport"
)

// fakeTransmitter records what it was asked to write.
type fakeTransmitter struct {
	linkType uint32
	linkErr  error

	gotIface  string
	gotFrames [][]byte
	stats     transport.TransmitStats
	err       error
}

func (f *fakeTransmitter) TransmitLinkType(string) (uint32, error) {
	return f.linkType, f.linkErr
}

func (f *fakeTransmitter) Transmit(_ context.Context, iface string, frames [][]byte) (transport.TransmitStats, error) {
	f.gotIface, f.gotFrames = iface, frames
	return f.stats, f.err
}

// fakeListener replays a fixed set of frames, then stops.
type fakeListener struct {
	frames [][]byte
	err    error
	calls  int
}

func (f *fakeListener) Capture(ctx context.Context, _ string, visit func(time.Time, []byte) error) (transport.CaptureStats, error) {
	f.calls++
	var stats transport.CaptureStats
	for _, frame := range f.frames {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		if err := visit(time.Now().UTC(), frame); err != nil {
			return stats, err
		}
		stats.Packets++
		stats.Bytes += uint64(len(frame))
	}
	return stats, f.err
}

func frames(n int) [][]byte {
	out := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, []byte(fmt.Sprintf("frame-%03d", i)))
	}
	return out
}

func TestTransmitAndListenRefusesBeforeTouchingTheKernel(t *testing.T) {
	tests := []struct {
		name     string
		tx       Transmitter
		options  Options
		wantErr  string
		wantSent bool
	}{
		{
			name:    "no transmitter",
			tx:      nil,
			options: Options{Interface: "wlan0", Frames: frames(1)},
			wantErr: "no transmitter",
		},
		{
			name:    "no interface",
			tx:      &fakeTransmitter{linkType: 127},
			options: Options{Frames: frames(1)},
			wantErr: "an interface is required",
		},
		{
			name:    "no frames",
			tx:      &fakeTransmitter{linkType: 127},
			options: Options{Interface: "wlan0"},
			wantErr: "no frames to transmit",
		},
		{
			// A count above the ceiling is refused rather than clamped, because
			// clamping would silently run a different test than the one asked for.
			name:    "above the harness frame ceiling",
			tx:      &fakeTransmitter{linkType: 127},
			options: Options{Interface: "wlan0", Frames: frames(MaxFramesPerRun + 1)},
			wantErr: "above the 256 frame ceiling",
		},
		{
			name:    "above the module frame cap",
			tx:      &fakeTransmitter{linkType: 127},
			options: Options{Interface: "wlan0", Frames: frames(6), FrameCap: 5},
			wantErr: "above the 5 frame ceiling",
		},
		{
			name:    "negative listen window",
			tx:      &fakeTransmitter{linkType: 127},
			options: Options{Interface: "wlan0", Frames: frames(1), ListenFor: -time.Second},
			wantErr: "listen window -1s is negative",
		},
		{
			name:    "listen window above the ceiling",
			tx:      &fakeTransmitter{linkType: 127},
			options: Options{Interface: "wlan0", Frames: frames(1), ListenFor: MaxListenWindow + time.Second},
			wantErr: "above the 30s ceiling",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder, _ := test.tx.(*fakeTransmitter)
			result, err := TransmitAndListen(context.Background(), test.tx, nil, test.options)
			if err == nil {
				t.Fatalf("expected a refusal, got result %+v", result)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %q, want it to mention %q", err, test.wantErr)
			}
			// A refused run must not have reached the write path at all.
			if recorder != nil && recorder.gotFrames != nil {
				t.Fatalf("a refused run wrote %d frame(s) to the kernel", len(recorder.gotFrames))
			}
			if result.FramesTransmitted != 0 {
				t.Fatalf("a refused run reported %d frames transmitted", result.FramesTransmitted)
			}
		})
	}
}

func TestTransmitAndListenReturnsTransmitFailure(t *testing.T) {
	tx := &fakeTransmitter{linkType: 127, err: errors.New("kernel refused the frame")}
	listener := &fakeListener{frames: frames(3)}

	result, err := TransmitAndListen(context.Background(), tx, listener, Options{
		Interface: "wlan0", Frames: frames(4), ListenFor: time.Second,
	})
	if err == nil {
		t.Fatal("a transmit failure must be returned, not carried only in the result")
	}
	if !strings.Contains(err.Error(), "kernel refused the frame") {
		t.Fatalf("error = %q, want the transmit failure", err)
	}
	// Nothing may be queued after a failed write.
	if result.TransmitError == nil {
		t.Fatal("the result must still record why transmission stopped")
	}
	// Listening for an answer to a frame that was never queued would manufacture
	// a negative result.
	if listener.calls != 0 {
		t.Fatalf("a failed transmit opened a listen window %d time(s)", listener.calls)
	}
}

// A refused write that accepted some frames must report the partial count, so a
// caller can say "sent 3 of 10" rather than "sent nothing" or "sent all 10".
func TestTransmitAndListenReportsPartialTransmit(t *testing.T) {
	tx := &fakeTransmitter{linkType: 127, stats: transport.TransmitStats{Frames: 3, Bytes: 27}, err: errors.New("stopped")}

	result, err := TransmitAndListen(context.Background(), tx, nil, Options{
		Interface: "wlan0", Frames: frames(10),
	})
	if err == nil {
		t.Fatal("expected the partial-transmit failure")
	}
	if result.FramesTransmitted != 3 || result.BytesTransmitted != 27 {
		t.Fatalf("partial counts = %d frames / %d bytes, want 3 / 27",
			result.FramesTransmitted, result.BytesTransmitted)
	}
}

// Nothing in this harness may claim a frame reached the air.
func TestResultNeverConfirmsDelivery(t *testing.T) {
	tx := &fakeTransmitter{linkType: 127, stats: transport.TransmitStats{Frames: 2, Bytes: 18}}
	result, err := TransmitAndListen(context.Background(), tx, nil, Options{
		Interface: "wlan0", Frames: frames(2),
	})
	if err != nil {
		t.Fatalf("transmit: %v", err)
	}
	if result.OverAirConfirmed() {
		t.Fatal("OverAirConfirmed must never be true")
	}
	if result.FramesTransmitted != 2 {
		t.Fatalf("frames transmitted = %d, want 2", result.FramesTransmitted)
	}
	if len(result.Limitations()) == 0 {
		t.Fatal("a completed run must still carry its delivery limitations")
	}
}

func TestResultDigestIdentifiesTheExactFrames(t *testing.T) {
	tx := &fakeTransmitter{linkType: 127}
	first, err := TransmitAndListen(context.Background(), tx, nil, Options{
		Interface: "wlan0", Frames: frames(3),
	})
	if err != nil {
		t.Fatalf("transmit: %v", err)
	}
	again, err := TransmitAndListen(context.Background(), tx, nil, Options{
		Interface: "wlan0", Frames: frames(3),
	})
	if err != nil {
		t.Fatalf("transmit: %v", err)
	}
	other, err := TransmitAndListen(context.Background(), tx, nil, Options{
		Interface: "wlan0", Frames: frames(4),
	})
	if err != nil {
		t.Fatalf("transmit: %v", err)
	}

	if first.Digest == "" || len(first.Digest) != 64 {
		t.Fatalf("digest = %q, want 64 hex characters", first.Digest)
	}
	if first.Digest != again.Digest {
		t.Fatal("identical frame sets must digest identically")
	}
	if first.Digest == other.Digest {
		t.Fatal("different frame sets must not share a digest")
	}
}

func TestTransmitAndListenObservesFrames(t *testing.T) {
	tx := &fakeTransmitter{linkType: 127, stats: transport.TransmitStats{Frames: 2, Bytes: 18}}
	listener := &fakeListener{frames: [][]byte{[]byte("alpha"), []byte("beta")}}

	result, err := TransmitAndListen(context.Background(), tx, listener, Options{
		Interface: "wlan0", Frames: frames(2), ListenFor: 5 * time.Second,
		Summarize: func(b []byte) (string, error) { return "frame of " + fmt.Sprint(len(b)) + " bytes", nil },
		Now:       func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if result.ObserveError() != nil {
		t.Fatalf("listen error: %v", result.ObserveError())
	}
	if len(result.Frames) != 2 {
		t.Fatalf("retained %d frames, want 2", len(result.Frames))
	}
	if result.ListenedFor != 5*time.Second {
		t.Fatalf("listened for %s, want 5s", result.ListenedFor)
	}
	if result.Frames[0].Summary != "frame of 5 bytes" {
		t.Fatalf("summary = %q, want the decoder's output", result.Frames[0].Summary)
	}
	if result.TransmitError != nil {
		t.Fatalf("unexpected transmit error: %v", result.TransmitError)
	}
}

func TestLinkTypeIsAskedOnlyWhenNotSupplied(t *testing.T) {
	asked := &fakeTransmitter{linkType: 127}
	if _, err := TransmitAndListen(context.Background(), asked, nil, Options{
		Interface: "wlan0", Frames: frames(1),
	}); err != nil {
		t.Fatalf("run: %v", err)
	}

	supplied := &fakeTransmitter{linkType: 127}
	result, err := TransmitAndListen(context.Background(), supplied, nil, Options{
		Interface: "wlan0", Frames: frames(1), LinkType: 105,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if result.LinkType != 105 {
		t.Fatalf("link type = %d, want the supplied 105", result.LinkType)
	}
}

// The harness must be able to tell the caller when it cannot even name the
// link type, rather than guessing a header format.
func TestLinkTypeFailureIsReported(t *testing.T) {
	tx := &fakeTransmitter{linkErr: errors.New("interface wlan0 does not exist")}
	_, err := TransmitAndListen(context.Background(), tx, nil, Options{
		Interface: "wlan0", Frames: frames(1),
	})
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("error = %v, want the link-type failure", err)
	}
	if tx.gotFrames != nil {
		t.Fatal("no frame may be written when the link type is unknown")
	}
}

// The collector is a ring, so a long observation cannot exhaust memory, and the
// drop is counted because a silent truncation reads as a quiet radio.
func TestCollectorBoundsAndCountsDrops(t *testing.T) {
	collector := NewCollector()
	total := MaxRetainedFrames + 100
	for i := 0; i < total; i++ {
		collector.Add(Frame{ObservedAt: time.Now().UTC(), Bytes: []byte(fmt.Sprintf("frame-%06d", i))})
	}
	if got := len(collector.Frames()); got != MaxRetainedFrames {
		t.Fatalf("retained %d frames, want the %d ceiling", got, MaxRetainedFrames)
	}
	if collector.Dropped() != 100 {
		t.Fatalf("dropped = %d, want 100", collector.Dropped())
	}
	if collector.Seen() != uint64(total) {
		t.Fatalf("seen = %d, want %d", collector.Seen(), total)
	}
	// The newest survive and the oldest are the ones dropped.
	retained := collector.Frames()
	if !strings.HasSuffix(string(retained[len(retained)-1].Bytes), fmt.Sprintf("frame-%06d", total-1)) {
		t.Fatalf("last retained = %q, want the newest frame", retained[len(retained)-1].Bytes)
	}
	if strings.Contains(string(retained[0].Bytes), "frame-000000") {
		t.Fatalf("first retained = %q, want the oldest frame already dropped", retained[0].Bytes)
	}
}
