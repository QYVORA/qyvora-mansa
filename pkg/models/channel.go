package models

// Band represents a frequency band.
type Band string

const (
	Band24GHz   Band = "2.4GHz"
	Band5GHz    Band = "5GHz"
	Band6GHz    Band = "6GHz"
	BandUnknown Band = "unknown"
)

// ChannelInfo maps a channel number to its frequency and band.
type ChannelInfo struct {
	Channel   int  `json:"channel"`
	Frequency int  `json:"frequency"`
	Band      Band `json:"band"`
}

// ChannelMap is the canonical channel→frequency→band lookup for 2.4 GHz.
var ChannelMap24GHz = map[int]int{
	1: 2412, 2: 2417, 3: 2422, 4: 2427, 5: 2432,
	6: 2437, 7: 2442, 8: 2447, 9: 2452, 10: 2457,
	11: 2462, 12: 2467, 13: 2472, 14: 2484,
}

// FreqToChannel converts a frequency in MHz to channel info.
func FreqToChannel(freq int) ChannelInfo {
	switch {
	case freq >= 2412 && freq <= 2484:
		ch := (freq-2412)/5 + 1
		if freq == 2484 {
			ch = 14
		}
		return ChannelInfo{Channel: ch, Frequency: freq, Band: Band24GHz}
	case freq >= 5170 && freq <= 5825:
		ch := (freq - 5000) / 5
		return ChannelInfo{Channel: ch, Frequency: freq, Band: Band5GHz}
	case freq >= 5955 && freq <= 7115:
		ch := (freq - 5950) / 5
		return ChannelInfo{Channel: ch, Frequency: freq, Band: Band6GHz}
	default:
		return ChannelInfo{Channel: 0, Frequency: freq, Band: BandUnknown}
	}
}

// ChannelToFreq returns the frequency for a 2.4 GHz channel, or 0.
func ChannelToFreq(ch int) int {
	if f, ok := ChannelMap24GHz[ch]; ok {
		return f
	}
	return 0
}

// OverlappingChannels reports channels that overlap in 2.4 GHz.
func OverlappingChannels(ch int) []int {
	used := map[int]bool{ch: true}
	switch {
	case ch <= 4:
		used[1] = true
		used[5] = true
	case ch <= 8:
		used[1] = true
		used[5] = true
		used[9] = true
	case ch <= 13:
		used[9] = true
		used[13] = true
	default:
		return nil
	}
	overlap := make([]int, 0)
	for c := range used {
		if c != ch {
			overlap = append(overlap, c)
		}
	}
	return overlap
}
