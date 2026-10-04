//go:build linux

package transport

import "testing"

func TestParseIwChannelsUsesReportedChannelsAndFlags(t *testing.T) {
	got := parseIwChannels("\t* 2412 MHz [1] (20.0 dBm)\n\t 5180 MHz [36] (disabled)\n\t 5955 MHz [1] (no IR)\n")
	if len(got) != 3 {
		t.Fatalf("got %d channels: %+v", len(got), got)
	}
	if got[0].Band != "2.4GHz" || got[1].Band != "5GHz" || !got[1].Disabled || got[2].Band != "6GHz" || !got[2].NoIR {
		t.Fatalf("unexpected parsed channels: %+v", got)
	}
}
