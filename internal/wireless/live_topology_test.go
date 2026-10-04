package wireless

import (
	"testing"
	"time"
)

func TestTopologyTrackerEmitsEachAPAndClientOnce(t *testing.T) {
	tracker := NewTopologyTracker()
	at := time.Date(2026, 10, 3, 1, 2, 3, 0, time.UTC)
	bssid := [6]byte{0x02, 0, 0, 0, 0, 1}
	station := [6]byte{0x02, 0, 0, 0, 0, 2}
	beacon := liveBeaconFixture(bssid, "mansa-lab")
	if ap, client, err := tracker.Observe(linkTypeIEEE80211, at, beacon); err != nil || ap == nil || client != nil {
		t.Fatalf("first beacon: ap=%v client=%v err=%v", ap, client, err)
	} else if ap.BSSID != formatMAC(bssid) || ap.SSID != "mansa-lab" {
		t.Fatalf("unexpected AP: %+v", *ap)
	}
	if ap, client, err := tracker.Observe(linkTypeIEEE80211, at.Add(time.Second), beacon); err != nil || ap != nil || client != nil {
		t.Fatalf("repeat beacon should not rediscover: ap=%v client=%v err=%v", ap, client, err)
	}
	probe := liveProbeFixture(station)
	if ap, client, err := tracker.Observe(linkTypeIEEE80211, at, probe); err != nil || ap != nil || client == nil {
		t.Fatalf("first probe: ap=%v client=%v err=%v", ap, client, err)
	} else if client.MAC != formatMAC(station) {
		t.Fatalf("unexpected client: %+v", *client)
	}
	if ap, client, err := tracker.Observe(linkTypeIEEE80211, at.Add(time.Second), probe); err != nil || ap != nil || client != nil {
		t.Fatalf("repeat probe should not rediscover: ap=%v client=%v err=%v", ap, client, err)
	}
}

func TestTopologyTrackerParsesRadiotapAndRejectsUnknownLink(t *testing.T) {
	tracker := NewTopologyTracker()
	frame := liveBeaconFixture([6]byte{0x02, 0, 0, 0, 0, 3}, "radio")
	radio := make([]byte, 8+len(frame))
	radio[2], radio[3] = 8, 0
	copy(radio[8:], frame)
	if ap, _, err := tracker.Observe(linkTypeRadiotap, time.Now(), radio); err != nil || ap == nil {
		t.Fatalf("radiotap beacon not discovered: ap=%v err=%v", ap, err)
	}
	if _, _, err := tracker.Observe(1, time.Now(), frame); err == nil {
		t.Fatal("unknown link type was accepted")
	}
}

func TestTopologyTrackerReportsHiddenSSIDRevealAndRoaming(t *testing.T) {
	tracker := NewTopologyTracker()
	at := time.Date(2026, 10, 3, 1, 2, 3, 0, time.UTC)
	firstAP, secondAP := [6]byte{0x02, 0, 0, 0, 0, 11}, [6]byte{0x02, 0, 0, 0, 0, 12}
	client := [6]byte{0x02, 0, 0, 0, 0, 21}
	if update, err := tracker.ObserveDetailed(linkTypeIEEE80211, at, liveBeaconFixture(firstAP, "")); err != nil || !update.AccessPointNew || update.AccessPoint == nil || !update.AccessPoint.Hidden {
		t.Fatalf("hidden AP: update=%+v err=%v", update, err)
	}
	if update, err := tracker.ObserveDetailed(linkTypeIEEE80211, at.Add(time.Second), liveBeaconFixture(firstAP, "revealed")); err != nil || update.AccessPointNew || update.AccessPoint == nil || update.AccessPoint.Hidden || update.AccessPoint.SSID != "revealed" {
		t.Fatalf("SSID reveal: update=%+v err=%v", update, err)
	}
	dataFrame := func(ap [6]byte) []byte {
		frame := make([]byte, 24)
		frame[0] = 0x08
		frame[1] = 0x01 // ToDS
		copy(frame[4:10], ap[:])
		copy(frame[10:16], client[:])
		return frame
	}
	if update, err := tracker.ObserveDetailed(linkTypeIEEE80211, at, dataFrame(firstAP)); err != nil || !update.StationNew {
		t.Fatalf("initial client observation: update=%+v err=%v", update, err)
	}
	if update, err := tracker.ObserveDetailed(linkTypeIEEE80211, at.Add(2*time.Second), dataFrame(secondAP)); err != nil || update.StationNew || update.Station == nil || update.RoamedFrom != formatMAC(firstAP) || update.Station.APBSSID != formatMAC(secondAP) {
		t.Fatalf("client roaming: update=%+v err=%v", update, err)
	}
}

func liveBeaconFixture(bssid [6]byte, ssid string) []byte {
	frame := make([]byte, 24+12+2+len(ssid)+3)
	frame[0] = 0x80 // beacon
	for offset := 4; offset <= 16; offset += 6 {
		copy(frame[offset:offset+6], bssid[:])
	}
	frame[24+10] = 0x11 // ESS + privacy capability
	frame[24+11] = 0x00
	frame[36], frame[37] = 0, byte(len(ssid))
	copy(frame[38:], ssid)
	pos := 38 + len(ssid)
	frame[pos], frame[pos+1], frame[pos+2] = 3, 1, 6
	return frame
}

func liveProbeFixture(station [6]byte) []byte {
	frame := make([]byte, 24+2)
	frame[0] = 0x40 // probe request
	for _, offset := range []int{4, 10} {
		copy(frame[offset:offset+6], station[:])
	}
	frame[16], frame[17] = 0, 0 // empty SSID element
	return frame
}
