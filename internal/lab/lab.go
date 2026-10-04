// Package lab is the shared transmit-and-observe harness used by both
// transmitting operation classes.
//
// It exists so the active-test and exploitation classes cannot drift apart on
// the properties that matter for safety. Every bound that limits a run lives
// here rather than in a module, and a module that needs to transmit goes through
// this harness to do it. Two modules written independently would each end up
// with their own idea of what a bounded run is.
//
// The harness reports what the kernel accepted. It never reports delivery: a
// successful write proves the frame was queued, not that it reached the air or
// that anything answered. Radio conditions produce the same observable silence
// as working protection, so silence is reported as silence.
package lab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/QYVORA/qyvora-mansa/internal/transport"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// The harness bounds. A module may declare something stricter; these are the
// ceilings no run may exceed, enforced here so a module cannot forget.
const (
	// MaxFramesPerRun caps frames handed to the kernel in one run.
	MaxFramesPerRun = 256

	// MaxListenWindow caps how long a run listens for a response.
	MaxListenWindow = 30 * time.Second

	// MaxRetainedFrames caps frames held for analysis. Beyond it the oldest
	// frames are dropped and the drop is counted, because a silently truncated
	// observation reads as a quiet radio.
	MaxRetainedFrames = 4096
)

// Transmitter is the raw frame write path this harness needs. It is declared
// here rather than imported so the harness does not depend on the executor.
type Transmitter interface {
	TransmitLinkType(iface string) (uint32, error)
	Transmit(ctx context.Context, iface string, frames [][]byte) (transport.TransmitStats, error)
}

// Listener is the passive read path this harness needs.
type Listener interface {
	Capture(ctx context.Context, iface string, visit func(time.Time, []byte) error) (transport.CaptureStats, error)
}

// Frame is one retained observed frame.
type Frame struct {
	ObservedAt time.Time
	Bytes      []byte
	// Summary is a short human description of the frame, when the harness could
	// decode one. It is a convenience for notes and evidence, never a finding.
	Summary string
}

// Options describes one transmit-and-observe run.
type Options struct {
	// Interface is the wireless interface used for both transmission and
	// listening. It must already be in monitor mode: the harness never changes
	// interface mode, channel, or association state.
	Interface string

	// Frames are the exact bytes to hand to the kernel, in order. Each must
	// already carry whatever header the transmit link type expects.
	Frames [][]byte

	// FrameCap is the module's own ceiling for this run. It must not exceed
	// MaxFramesPerRun. Zero means MaxFramesPerRun.
	FrameCap int

	// ListenFor is how long to listen after transmitting. It must not exceed
	// MaxListenWindow. Zero means no listening.
	ListenFor time.Duration

	// LinkType is the transmit link type recorded in the result. Zero means the
	// value is asked of the transmitter.
	LinkType uint32

	// Summarize decodes each observed frame into a short description. It is
	// optional; without it the harness retains raw bytes only.
	Summarize func([]byte) (string, error)

	// Now supplies the clock, injectable so a test need not sleep.
	Now func() time.Time
}

// Result is what a run observed.
//
// OverAirConfirmed is always false. The field exists so that no caller has to
// invent the claim: the absence of a way to set it is the guarantee.
type Result struct {
	// LinkType is the transmit link type the frames were written for.
	LinkType uint32

	// FramesTransmitted and BytesTransmitted are what the kernel accepted.
	FramesTransmitted uint64
	BytesTransmitted  uint64

	// Digest is a SHA-256 over the exact bytes handed to the kernel, so a
	// record can be tied to the frames that were sent without storing them.
	Digest string

	// Frames are the retained observations from the listen window.
	Frames []Frame

	// FramesSeen counts every frame the listener delivered, including those
	// dropped for retention.
	FramesSeen uint64

	// Malformed counts observed frames the summarizer refused to decode.
	Malformed uint64

	// Truncated counts observed frames dropped because retention was full.
	Truncated uint64

	// ListenedFor is how long the listen window actually ran.
	ListenedFor time.Duration

	// TransmitError is the error that ended transmission, when one did. The
	// frames accepted before it are still reported.
	TransmitError error

	// ListenError is the error that ended the listen window, when one did.
	ListenError error
}

// OverAirConfirmed reports whether any frame was confirmed to have reached the
// air. It is a constant false: this harness cannot establish it.
func (r Result) OverAirConfirmed() bool { return false }

// TransmitAndListen writes the supplied frames and then listens for responses.
//
// The order is deliberate. Listening starts after transmission so the window
// measures what the target did in response, not what this host was already
// hearing. Every bound is checked before anything is transmitted, so a request
// above a ceiling is refused rather than partially executed.
func TransmitAndListen(ctx context.Context, tx Transmitter, listener Listener, options Options) (Result, error) {
	result := Result{LinkType: options.LinkType}
	if tx == nil {
		return result, fmt.Errorf("no transmitter is available")
	}
	if options.Interface == "" {
		return result, fmt.Errorf("an interface is required")
	}
	if len(options.Frames) == 0 {
		return result, fmt.Errorf("no frames to transmit")
	}

	// The frame ceiling is checked first, against the tighter of the module's
	// cap and the harness ceiling. A count above it is refused rather than
	// clamped: clamping would run a different test than the one requested.
	cap := options.FrameCap
	if cap <= 0 || cap > MaxFramesPerRun {
		cap = MaxFramesPerRun
	}
	if len(options.Frames) > cap {
		return result, fmt.Errorf("run would transmit %d frames, above the %d frame ceiling", len(options.Frames), cap)
	}
	if options.ListenFor < 0 {
		return result, fmt.Errorf("listen window %s is negative", options.ListenFor)
	}
	if options.ListenFor > MaxListenWindow {
		return result, fmt.Errorf("listen window %s is above the %s ceiling", options.ListenFor, MaxListenWindow)
	}

	if result.LinkType == 0 {
		linkType, err := tx.TransmitLinkType(options.Interface)
		if err != nil {
			return result, fmt.Errorf("determine transmit link type: %w", err)
		}
		result.LinkType = linkType
	}

	// The digest covers the exact bytes transmitted, so the record identifies
	// the frames even though the frames themselves are not retained.
	digest := sha256.New()
	for _, frame := range options.Frames {
		digest.Write(frame)
	}
	result.Digest = hex.EncodeToString(digest.Sum(nil))

	stats, transmitErr := tx.Transmit(ctx, options.Interface, options.Frames)
	result.FramesTransmitted, result.BytesTransmitted = stats.Frames, stats.Bytes
	result.TransmitError = transmitErr
	if transmitErr != nil {
		// A transmit that the kernel refused still reports what it accepted, and
		// no listen window follows: listening for an answer to a frame that was
		// never queued would manufacture a negative result.
		//
		// The refusal is returned as an error. Carrying it only in the result
		// would let a caller that checks the error return and ignores the fields
		// report a run that transmitted nothing as though it had worked.
		return result, transmitErr
	}

	if options.ListenFor == 0 || listener == nil {
		return result, nil
	}
	observeErr := listen(ctx, listener, options, &result)
	result.ListenError = observeErr
	return result, nil
}

// Collector retains observed frames within a fixed bound.
//
// It is a ring: once full, the oldest frames are dropped and the drop is
// counted. A module that reports a count without the drop count would present a
// truncated window as a complete one.
type Collector struct {
	frames []Frame
	next   int
	full   bool
	seen   uint64
}

// NewCollector returns a collector holding at most MaxRetainedFrames.
func NewCollector() *Collector {
	return &Collector{frames: make([]Frame, 0, MaxRetainedFrames)}
}

// Add retains one frame, dropping the oldest once the bound is reached.
func (c *Collector) Add(frame Frame) {
	c.seen++
	if len(c.frames) < cap(c.frames) {
		c.frames = append(c.frames, frame)
		return
	}
	c.full = true
	c.frames[c.next] = frame
	c.next = (c.next + 1) % cap(c.frames)
}

// Frames returns the retained frames in arrival order.
func (c *Collector) Frames() []Frame {
	if !c.full {
		return append([]Frame(nil), c.frames...)
	}
	out := make([]Frame, 0, len(c.frames))
	out = append(out, c.frames[c.next:]...)
	out = append(out, c.frames[:c.next]...)
	return out
}

// Seen counts every frame offered to the collector, including dropped ones.
func (c *Collector) Seen() uint64 { return c.seen }

// Dropped counts the frames the bound discarded.
func (c *Collector) Dropped() uint64 {
	if !c.full {
		return 0
	}
	return c.seen - uint64(len(c.frames))
}

// listen runs the observation window. The window ends on its own deadline, so a
// capture provider that keeps waiting does not extend the run.
func listen(ctx context.Context, listener Listener, options Options, result *Result) error {
	collector := NewCollector()
	clock := options.Now
	if clock == nil {
		clock = time.Now
	}
	windowCtx, cancel := context.WithTimeout(ctx, options.ListenFor)
	defer cancel()

	_, err := listener.Capture(windowCtx, options.Interface, func(at time.Time, packet []byte) error {
		if len(packet) == 0 {
			return nil
		}
		observed := at
		if observed.IsZero() {
			observed = clock()
		}
		frame := Frame{ObservedAt: observed, Bytes: append([]byte(nil), packet...)}
		if options.Summarize != nil {
			summary, summarizeErr := options.Summarize(packet)
			if summarizeErr != nil {
				// A frame the summarizer cannot decode is counted, not fatal:
				// one unknown frame must not end a window that is otherwise
				// answering.
				result.Malformed++
			} else {
				frame.Summary = summary
			}
		}
		collector.Add(frame)
		return nil
	})

	result.Frames = collector.Frames()
	result.FramesSeen = collector.Seen()
	result.Truncated = collector.Dropped()
	result.ListenedFor = options.ListenFor

	if err != nil {
		// The deadline ending the window is the expected way out, not a failure.
		if windowCtx.Err() != nil && ctx.Err() == nil {
			return nil
		}
		return err
	}
	return nil
}

// Evidence renders the run's transmission as evidence.
//
// The evidence carries the accepted counts and the digest of the exact bytes.
// It deliberately carries no delivery claim: a reader of the record must not be
// able to mistake an accepted write for a confirmed transmission.
func (r Result) Evidence(source, target string) models.Evidence {
	detail := fmt.Sprintf(
		"the kernel accepted %d frame(s) totalling %d byte(s); over-air delivery is not established by an accepted write",
		r.FramesTransmitted, r.BytesTransmitted)
	if r.FramesSeen > 0 {
		detail += fmt.Sprintf("; %d frame(s) observed in a %s listen window", r.FramesSeen, r.ListenedFor)
	}
	if r.Truncated > 0 {
		detail += fmt.Sprintf("; %d observed frame(s) dropped at the %d frame retention bound", r.Truncated, MaxRetainedFrames)
	}
	if r.Malformed > 0 {
		detail += fmt.Sprintf("; %d observed frame(s) could not be decoded", r.Malformed)
	}
	return models.Evidence{
		ID:     models.NewID("evidence"),
		Kind:   models.EvidenceProtocol,
		Source: source,
		Target: target,
		Detail: detail,
		Hash:   r.Digest,
	}
}

// Limitations returns the statements a caller must record alongside any result
// from this harness. They are returned rather than left to each module so the
// two transmitting classes state the same caveats.
func (r Result) Limitations() []string {
	limitations := []string{
		"Frames transmitted is what the kernel accepted; it is not proof that any frame reached the air or that a device acted on it.",
	}
	if r.FramesSeen == 0 {
		limitations = append(limitations,
			"Nothing was observed in the listen window. Radio conditions and working protection produce the same silence, so this is not a negative result.")
	}
	if r.Truncated > 0 {
		limitations = append(limitations,
			fmt.Sprintf("The observation window exceeded the %d frame retention bound and %d frame(s) were dropped; counts describe the retained frames.", MaxRetainedFrames, r.Truncated))
	}
	return limitations
}

// ObserveError returns the error that ended the run's observation, if any.
// Transmission and observation errors are reported separately so a caller can
// distinguish "the frames were refused" from "the frames went out and nothing
// answered".
func (r Result) ObserveError() error { return r.ListenError }
