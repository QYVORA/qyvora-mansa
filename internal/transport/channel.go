package transport

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// RadioChannel is one channel exactly as the radio reported it. The fields are
// not derived: a disabled channel stays disabled, and a channel flagged no-IR
// keeps that flag so a caller can refuse to transmit on it.
type RadioChannel struct {
	// Number is the channel number the radio uses.
	Number int

	// Frequency is the centre frequency in MHz.
	Frequency int

	// Band is the frequency band label derived from Frequency.
	Band string

	// Disabled reports that the radio will not use this channel.
	Disabled bool

	// NoIR reports that the channel is restricted to passive use, because an
	// active scan would violate the regulatory domain.
	NoIR bool
}

// ChannelController reads and changes one interface's channel.
//
// It is deliberately not part of Backend: a provider may be able to capture
// frames while having no way to retune the radio, and conflating the two would
// make channel control look available everywhere.
type ChannelController interface {
	// Channels lists the channels the radio reports.
	Channels(ctx context.Context) ([]RadioChannel, error)

	// CurrentChannel reports the channel the interface is on now.
	CurrentChannel(ctx context.Context) (RadioChannel, error)

	// SetChannel retunes the interface. Implementations refuse a channel the
	// radio does not report as available rather than forcing it.
	SetChannel(ctx context.Context, channel RadioChannel) error
}

// ChannelAssignment pairs an interface with one channel it should sit on.
type ChannelAssignment struct {
	Interface string
	Channel   RadioChannel
}

// DefaultChannelDwell is the per-channel dwell used when a caller does not ask
// for one. It is short enough to be useful and long enough not to spin.
const DefaultChannelDwell = 250 * time.Millisecond

// RunChannelScheduleObserved cycles the given interfaces through their channel
// assignments until the context ends, calling observe after every successful
// change.
//
// Interfaces are retuned in lockstep rather than one after another, because
// sequential tuning would leave the interfaces on different channels for the
// length of every dwell and silently produce a capture that never saw the whole
// hop set at once.
//
// It returns the context error when it stops, so a caller can tell a finished
// schedule from a failed one. The caller owns restoring the prior channels: this
// function changes radio state and does not put it back.
func RunChannelScheduleObserved(
	ctx context.Context,
	controllers map[string]ChannelController,
	assignments []ChannelAssignment,
	dwell time.Duration,
	observe func(changedInterface string, channel RadioChannel),
) error {
	if len(assignments) == 0 {
		return nil
	}
	if dwell <= 0 {
		dwell = DefaultChannelDwell
	}

	// Group by interface, preserving each interface's requested order, and keep
	// the interfaces in a stable order so the schedule is reproducible.
	order := make([]string, 0, len(controllers))
	byInterface := make(map[string][]RadioChannel, len(controllers))
	for _, assignment := range assignments {
		if _, seen := byInterface[assignment.Interface]; !seen {
			byInterface[assignment.Interface] = nil
			order = append(order, assignment.Interface)
		}
		byInterface[assignment.Interface] = append(byInterface[assignment.Interface], assignment.Channel)
	}
	if len(byInterface) == 0 {
		return nil
	}
	sort.Strings(order)

	rounds := 0
	for _, channels := range byInterface {
		if len(channels) > rounds {
			rounds = len(channels)
		}
	}

	ticker := time.NewTicker(dwell)
	defer ticker.Stop()
	first := true
	for step := 0; ; step++ {
		if !first {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
		first = false
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, iface := range order {
			channels := byInterface[iface]
			if len(channels) == 0 {
				continue
			}
			controller, ok := controllers[iface]
			if !ok || controller == nil {
				return fmt.Errorf("no channel controller for interface %q", iface)
			}
			channel := channels[step%len(channels)]
			if err := controller.SetChannel(ctx, channel); err != nil {
				return fmt.Errorf("set channel %d on %s: %w", channel.Number, iface, err)
			}
			if observe != nil {
				observe(iface, channel)
			}
		}
		if rounds <= 1 {
			// Nothing to cycle through; hold the assignment until the context
			// ends rather than rewriting the same channel forever.
			<-ctx.Done()
			return ctx.Err()
		}
	}
}
