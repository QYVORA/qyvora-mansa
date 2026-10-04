package cli

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/QYVORA/qyvora-mansa/internal/exitcode"
)

func TestCaptureAnalyzeSavesEvidenceBackedSession(t *testing.T) {
	resetTestApp(t)
	path := filepath.Join(t.TempDir(), "wireless.pcap")
	if err := os.WriteFile(path, testBeaconPCAP(), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ExecuteArgs(context.Background(), []string{"capture", "analyze", path, "-o", "json"}); got != exitcode.Success {
		t.Fatalf("capture analyze exit code = %d", got)
	}
	sess, err := appState.LatestSession()
	if err != nil {
		t.Fatal(err)
	}
	if !sess.Offline || len(sess.AccessPoints) != 1 || sess.AccessPoints[0].SSID != "lab-ap" {
		t.Fatalf("session import = %+v", sess)
	}
	if len(sess.Evidence) != 1 || len(sess.Evidence[0].Hash) != 64 || sess.Evidence[0].Source != "classic-pcap" {
		t.Fatalf("capture evidence = %+v", sess.Evidence)
	}
	if sess.Attributes["capture_packets"] != "1" {
		t.Errorf("capture packet count = %q", sess.Attributes["capture_packets"])
	}
}

func TestCaptureLiveRequiresInterface(t *testing.T) {
	resetTestApp(t)
	if got := ExecuteArgs(context.Background(), []string{"capture", "live"}); got != exitcode.Usage {
		t.Fatalf("capture live without interface exit code = %d, want usage", got)
	}
}

func TestCaptureLiveSimulationCreatesEvidenceSession(t *testing.T) {
	resetTestApp(t)
	path := filepath.Join(t.TempDir(), "simulated.pcap")
	if got := ExecuteArgs(context.Background(), []string{"capture", "live", "--sim", "--out", path, "-o", "json"}); got != exitcode.Success {
		t.Fatalf("simulated live capture exit code = %d", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("capture output permissions = %o, want 600", info.Mode().Perm())
	}
	sess, err := appState.LatestSession()
	if err != nil {
		t.Fatal(err)
	}
	if !sess.Simulated || len(sess.AccessPoints) != 1 || sess.AccessPoints[0].SSID != "SimLab-AP" || len(sess.Stations) != 1 {
		t.Fatalf("simulated capture session = %+v", sess)
	}
	for _, finding := range sess.Findings {
		if finding.RuleID == "WLAN-020" {
			t.Errorf("missing capture RSSI generated a signal finding: %+v", finding)
		}
	}
	if len(sess.Evidence) != 1 || sess.Evidence[0].Source != "live-pcap" || len(sess.Evidence[0].Hash) != 64 {
		t.Fatalf("simulated capture evidence = %+v", sess.Evidence)
	}
}

func TestCaptureLiveStreamsTopologyEventsBeforeAnalysis(t *testing.T) {
	resetTestApp(t)
	defer func() { eventsFlag = "" }()
	dir := t.TempDir()
	capturePath := filepath.Join(dir, "live.pcap")
	eventsPath := filepath.Join(dir, "events.jsonl")
	args := []string{"capture", "live", "--sim", "--out", capturePath, "--events", eventsPath, "-o", "json"}
	if got := ExecuteArgs(context.Background(), args); got != exitcode.Success {
		t.Fatalf("simulated live capture exit code = %d", got)
	}

	type wireEvent struct {
		Event string         `json:"event"`
		Data  map[string]any `json:"data"`
	}
	file, err := os.Open(eventsPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var seen []wireEvent
	var liveAP, liveClient int
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event wireEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("decode event: %v", err)
		}
		seen = append(seen, event)
		if event.Data["source"] == "live-capture" && event.Event == "access_point.discovered" {
			liveAP++
		}
		if event.Data["source"] == "live-capture" && event.Event == "client.discovered" {
			liveClient++
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if liveAP != 1 || liveClient != 1 {
		t.Fatalf("live discovery counts: AP=%d client=%d, want one each", liveAP, liveClient)
	}
	firstLiveDiscovery, analysisStart := -1, -1
	for i, event := range seen {
		if event.Data["source"] == "live-capture" &&
			(event.Event == "access_point.discovered" || event.Event == "client.discovered") && firstLiveDiscovery < 0 {
			firstLiveDiscovery = i
		}
		if event.Event == "scan.started" && analysisStart < 0 {
			analysisStart = i
		}
	}
	if firstLiveDiscovery < 0 || analysisStart < 0 || firstLiveDiscovery >= analysisStart {
		t.Fatalf("live discovery was not emitted before final analysis: events=%+v", seen)
	}
}

func testBeaconPCAP() []byte {
	frame := make([]byte, 36)
	binary.LittleEndian.PutUint16(frame, uint16(8<<4))
	copy(frame[10:16], []byte{0x02, 0, 0, 0, 0, 1})
	copy(frame[16:22], []byte{0x02, 0, 0, 0, 0, 1})
	frame = append(frame, 0, 6, 'l', 'a', 'b', '-', 'a', 'p', 3, 1, 1)

	pcap := make([]byte, 24+16+len(frame))
	copy(pcap, []byte{0xd4, 0xc3, 0xb2, 0xa1})
	binary.LittleEndian.PutUint16(pcap[4:6], 2)
	binary.LittleEndian.PutUint16(pcap[6:8], 4)
	binary.LittleEndian.PutUint32(pcap[16:20], 65535)
	binary.LittleEndian.PutUint32(pcap[20:24], 105)
	binary.LittleEndian.PutUint32(pcap[24:28], 10)
	binary.LittleEndian.PutUint32(pcap[32:36], uint32(len(frame)))
	binary.LittleEndian.PutUint32(pcap[36:40], uint32(len(frame)))
	copy(pcap[40:], frame)
	return pcap
}

func TestCaptureLiveRejectsKernelPrefilterWithSimulation(t *testing.T) {
	for _, args := range [][]string{
		{"capture", "live", "--sim", "--prefilter", "assessment"},
		{"capture", "live", "--sim", "--prefilter", "assessment", "--prefilter-address", "de:ad:be:ef:00:01"},
	} {
		if got := ExecuteArgs(context.Background(), args); got != exitcode.Usage {
			t.Fatalf("%v: exit code = %d, want %d", args, got, exitcode.Usage)
		}
	}
}

func TestCaptureLiveAdvertisesKernelPrefilterFlag(t *testing.T) {
	command := newCaptureLiveCmd()
	for _, name := range []string{"prefilter", "prefilter-address"} {
		if command.Flags().Lookup(name) == nil {
			t.Errorf("capture live is missing the --%s flag", name)
		}
	}
	if got := command.Flags().Lookup("prefilter").DefValue; got != "all" {
		t.Errorf("the default prefilter mode is %q, want all so capture is unfiltered by default", got)
	}
}
