//go:build linux

package transport

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

var iwChannelLine = regexp.MustCompile(`^\*?\s*([0-9]+) MHz \[([0-9]+)\](.*)$`)
var iwCurrentChannel = regexp.MustCompile(`channel ([0-9]+) \(([0-9]+) MHz\)`)

// LinuxChannelController uses the host's iw/cfg80211 channel inventory. It
// does not synthesize channel lists, change regulatory settings, or transmit.
type LinuxChannelController struct{ Interface string }

func (c LinuxChannelController) Channels(ctx context.Context) ([]RadioChannel, error) {
	phy, err := c.phy(ctx)
	if err != nil {
		return nil, err
	}
	out, err := exec.CommandContext(ctx, "iw", "phy", phy, "info").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("query channels for %s: %w: %s", c.Interface, err, strings.TrimSpace(string(out)))
	}
	return parseIwChannels(string(out)), nil
}

func (c LinuxChannelController) CurrentChannel(ctx context.Context) (RadioChannel, error) {
	out, err := exec.CommandContext(ctx, "iw", "dev", c.Interface, "info").CombinedOutput()
	if err != nil {
		return RadioChannel{}, fmt.Errorf("query current channel for %s: %w: %s", c.Interface, err, strings.TrimSpace(string(out)))
	}
	for _, line := range strings.Split(string(out), "\n") {
		match := iwCurrentChannel.FindStringSubmatch(line)
		if len(match) == 3 {
			frequency, _ := strconv.Atoi(match[2])
			number, _ := strconv.Atoi(match[1])
			return RadioChannel{Number: number, Frequency: frequency, Band: bandForFrequency(frequency)}, nil
		}
	}
	return RadioChannel{}, fmt.Errorf("interface %s has no active channel", c.Interface)
}

func (c LinuxChannelController) SetChannel(ctx context.Context, channel RadioChannel) error {
	channels, err := c.Channels(ctx)
	if err != nil {
		return err
	}
	available := false
	for _, candidate := range channels {
		if candidate.Frequency == channel.Frequency && candidate.Number == channel.Number && !candidate.Disabled {
			available = true
			break
		}
	}
	if !available {
		return fmt.Errorf("channel %d (%d MHz) is not available on %s", channel.Number, channel.Frequency, c.Interface)
	}
	out, err := exec.CommandContext(ctx, "iw", "dev", c.Interface, "set", "channel", strconv.Itoa(channel.Number)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("set channel on %s: %w: %s", c.Interface, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (c LinuxChannelController) phy(ctx context.Context) (string, error) {
	if strings.TrimSpace(c.Interface) == "" {
		return "", fmt.Errorf("wireless interface is required")
	}
	out, err := exec.CommandContext(ctx, "iw", "dev", c.Interface, "info").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("query radio for %s: %w: %s", c.Interface, err, strings.TrimSpace(string(out)))
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 2 && fields[0] == "wiphy" {
			return "phy" + fields[1], nil
		}
	}
	return "", fmt.Errorf("iw did not report a radio for %s", c.Interface)
}

func parseIwChannels(output string) []RadioChannel {
	channels := make([]RadioChannel, 0)
	for _, line := range strings.Split(output, "\n") {
		match := iwChannelLine.FindStringSubmatch(strings.TrimSpace(line))
		if len(match) != 4 {
			continue
		}
		frequency, e1 := strconv.Atoi(match[1])
		number, e2 := strconv.Atoi(match[2])
		if e1 != nil || e2 != nil || frequency <= 0 || number <= 0 {
			continue
		}
		flags := strings.ToUpper(match[3])
		channels = append(channels, RadioChannel{Number: number, Frequency: frequency, Band: bandForFrequency(frequency), Disabled: strings.Contains(flags, "DISABLED"), NoIR: strings.Contains(flags, "NO-IR") || strings.Contains(flags, "NO IR")})
	}
	return channels
}

func bandForFrequency(frequency int) string {
	switch {
	case frequency >= 2400 && frequency < 2500:
		return "2.4GHz"
	case frequency >= 4900 && frequency < 5925:
		return "5GHz"
	case frequency >= 5925 && frequency <= 7125:
		return "6GHz"
	default:
		return "unknown"
	}
}
