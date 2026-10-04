//go:build linux

package transport

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/QYVORA/qyvora-mansa/internal/bluetooth"
	"golang.org/x/sys/unix"
)

func TestParseBluetoothAddressAcceptsBothSeparators(t *testing.T) {
	for _, value := range []string{"AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"} {
		address, err := parseBluetoothAddress(value)
		if err != nil {
			t.Fatalf("%s: %v", value, err)
		}
		if got := address.String(); got != "AA:BB:CC:DD:EE:FF" {
			t.Errorf("%s rendered as %q", value, got)
		}
		bytes := address.Bytes()
		if bytes[0] != 0xff || bytes[5] != 0xaa {
			t.Errorf("%s HCI bytes % x, want ff ee dd cc bb aa", value, bytes)
		}
	}
}

func TestParseBluetoothAddressRejectsBadInput(t *testing.T) {
	for _, value := range []string{
		"", "AA:BB:CC:DD:EE", "AA:BB:CC:DD:EE:FF:00", "GG:BB:CC:DD:EE:FF",
		"AA-BB-CC-DD-EE-FF", "AABBCCDDEEFF", "AA:BB:CC:DD:EE:GG", "hci0",
	} {
		if address, err := parseBluetoothAddress(value); err == nil {
			t.Errorf("%q must be refused, got %+v", value, address)
		}
	}
}

func TestParseHCIIndexRefusesNonAdapters(t *testing.T) {
	if _, err := parseHCIIndex("not-an-adapter"); err == nil {
		t.Error("a non-adapter name must be refused")
	}
	if _, err := parseHCIIndex("hci"); err == nil {
		t.Error("a bare name without an index must be refused")
	}
	if index, err := parseHCIIndex("hci0"); err != nil || index != 0 {
		t.Errorf("hci0 = %d, %v", index, err)
	}
}

func TestParseACLSelectsOnlyTheRequestedChannel(t *testing.T) {
	// An ACL data event: event code, handle, length, then the L2CAP frame.
	event := func(handle, cid uint16, payload []byte) []byte {
		packet := make([]byte, 4+4+len(payload))
		binary.LittleEndian.PutUint16(packet[0:2], handle)
		binary.LittleEndian.PutUint16(packet[2:4], hciACLStartFlushable)
		binary.LittleEndian.PutUint16(packet[4:6], uint16(l2capCIDBytes+len(payload)))
		binary.LittleEndian.PutUint16(packet[6:8], cid)
		copy(packet[8:], payload)
		return packet
	}

	body := []byte{bluetooth.ATTReadByTypeResponse, 0x01}
	payload, err := parseACLPayload(event(0x000c, l2capCIDATT, body), 0x000c, l2capCIDATT)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != len(body) || payload[0] != bluetooth.ATTReadByTypeResponse {
		t.Errorf("payload = % x", payload)
	}
	// Another link and another channel are not this link's traffic.
	if payload, err := parseACLPayload(event(0x000d, l2capCIDATT, body), 0x000c, l2capCIDATT); err != nil || payload != nil {
		t.Errorf("a packet for another handle = % x, %v", payload, err)
	}
	if payload, err := parseACLPayload(event(0x000c, 0x0006, body), 0x000c, l2capCIDATT); err != nil || payload != nil {
		t.Errorf("a packet for another channel = % x, %v", payload, err)
	}
}

func TestParseACLRefusesMalformedFrames(t *testing.T) {
	short := []byte{0x0c, 0x00, 0x02, 0x00} // truncated
	if _, err := parseACLPayload(short, 0x000c, l2capCIDATT); err == nil {
		t.Error("a truncated ACL packet must be refused")
	}
	// An L2CAP length longer than the packet that carries it.
	lying := []byte{0x0c, 0x00, 0x02, 0x00, 0x40, 0x00, 0x04, 0x00, 0x01, 0x02}
	if _, err := parseACLPayload(lying, 0x000c, l2capCIDATT); err == nil {
		t.Error("L2CAP length beyond the packet must be refused")
	}
	// A length below the CID it must contain.
	shortLength := []byte{0x0c, 0x00, 0x02, 0x00, 0x02, 0x00, 0x04, 0x00, 0x01, 0x02}
	if _, err := parseACLPayload(shortLength, 0x000c, l2capCIDATT); err == nil {
		t.Error("L2CAP length shorter than its CID must be refused")
	}
}

func TestFragmentPDUsRespectsTheNegotiatedMTU(t *testing.T) {
	// The usable payload is the MTU less the ACL and L2CAP headers.
	capacity := 23 - aclHeaderBytes - l2capLengthBytes - l2capCIDBytes
	if capacity != 15 {
		t.Fatalf("a 23-byte MTU leaves %d bytes, want 15", capacity)
	}
	pdu := make([]byte, 40)
	for i := range pdu {
		pdu[i] = byte(i)
	}
	fragments := fragmentPDUs(pdu, 23)
	if len(fragments) != 3 {
		t.Fatalf("got %d fragments, want 3", len(fragments))
	}
	rebuilt := make([]byte, 0, len(pdu))
	for index, fragment := range fragments {
		if len(fragment) > capacity {
			t.Errorf("fragment %d carries %d bytes, more than the %d the MTU allows", index, len(fragment), capacity)
		}
		rebuilt = append(rebuilt, fragment...)
	}
	if string(rebuilt) != string(pdu) {
		t.Error("fragmenting must preserve the PDU exactly")
	}

	// A PDU that already fits is sent whole.
	if whole := fragmentPDUs(pdu[:capacity], 23); len(whole) != 1 || string(whole[0]) != string(pdu[:capacity]) {
		t.Errorf("a PDU within the MTU must not be split, got %d fragments", len(whole))
	}
	// A larger MTU carries more per packet.
	if wide := fragmentPDUs(pdu, 247); len(wide) != 1 {
		t.Errorf("a 247-byte MTU must carry the 40-byte PDU whole, got %d fragments", len(wide))
	}
}

func TestFragmentPDUsDoesNotExceedTheNegotiatedMTU(t *testing.T) {
	// The controller's largest ACL payload must not be used as a floor: a peer
	// that negotiated a small MTU must not receive larger fragments.
	pdu := make([]byte, 300)
	for _, fragment := range fragmentPDUs(pdu, 23) {
		if len(fragment) > 23-aclHeaderBytes-l2capLengthBytes-l2capCIDBytes {
			t.Fatalf("a fragment of %d bytes exceeds a 23-byte MTU", len(fragment))
		}
	}
}

func TestATTResponseOpcodePairs(t *testing.T) {
	for _, request := range []byte{
		bluetooth.ATTExchangeMTURequest, bluetooth.ATTFindInformationRequest,
		bluetooth.ATTReadByTypeRequest, bluetooth.ATTReadByGroupTypeRequest,
	} {
		response, ok := attResponseOpcode(request)
		if !ok {
			t.Errorf("request 0x%02x must have a response", request)
		}
		if response != request+1 {
			t.Errorf("request 0x%02x is answered by 0x%02x, got 0x%02x", request, request+1, response)
		}
	}
	// A request with no response must be reported so a caller does not wait for one.
	for _, request := range []byte{bluetooth.ATTErrorResponse, 0x0a, 0x52} {
		if _, ok := attResponseOpcode(request); ok {
			t.Errorf("request 0x%02x has no response and must report false", request)
		}
	}
}

func TestGATTEnumerationRefusesAnEmptyAddress(t *testing.T) {
	backend := &LinuxBackend{}
	if _, err := backend.EnumerateGATT(context.Background(), "hci0", "", GATTEnumerationOptions{}); err == nil {
		t.Error("an enumeration without a peer address must be refused")
	}
}

func TestGATTEnumerationRefusesABadAddress(t *testing.T) {
	backend := &LinuxBackend{}
	if _, err := backend.EnumerateGATT(context.Background(), "hci0", "not-an-address", GATTEnumerationOptions{}); err == nil {
		t.Error("an enumeration with a malformed address must be refused")
	}
}

func TestSimulatedBackendRefusesLiveEnumeration(t *testing.T) {
	// The deterministic fixture must never be presented as a live peer's table.
	if _, err := New().EnumerateGATT(context.Background(), "hci0", "AA:BB:CC:DD:EE:FF", GATTEnumerationOptions{}); err == nil {
		t.Fatal("the simulated backend must refuse live GATT enumeration")
	}
}

// scriptedPeer is a socket pair standing in for a controller and a peer. Requests
// written to it are answered from a scripted table of responses.
type scriptedPeer struct {
	fd        int
	responses map[byte][]byte
	requests  [][]byte
}

// newScriptedPeer returns an attLink whose transport is a socket pair. The peer end
// is scripted by the test.
func newScriptedPeer(t *testing.T, mtu uint16) (*attLink, *scriptedPeer) {
	t.Helper()
	client, server, err := socketPair()
	if err != nil {
		t.Skipf("cannot create a socket pair: %v", err)
	}
	t.Cleanup(func() {
		unix.Close(client)
		unix.Close(server)
	})
	if err := unix.SetNonblock(server, true); err != nil {
		t.Fatal(err)
	}
	peer, err := parseBluetoothAddress("AA:BB:CC:DD:EE:FF")
	if err != nil {
		t.Fatal(err)
	}
	return &attLink{fd: client, peer: peer, handle: 0x000c, mtu: mtu}, &scriptedPeer{fd: server, responses: map[byte][]byte{}}
}

// serve answers every request the client sends and runs until the client stops.
// The response for a request opcode is taken from the script, so a walk can be
// driven without a controller.
func (s *scriptedPeer) serve(t *testing.T, ctx context.Context, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return
		}
		buf := make([]byte, 4096)
		n, _, err := unix.Recvfrom(s.fd, buf, 0)
		if err != nil {
			if isRetryableSocketError(err) {
				time.Sleep(time.Millisecond)
				continue
			}
			return
		}
		// Unwrap the ACL packet and the L2CAP frame to reach the ATT PDU.
		if n < 4+l2capLengthBytes+l2capCIDBytes {
			continue
		}
		pdu := buf[4+l2capLengthBytes+l2capCIDBytes : n]
		s.requests = append(s.requests, append([]byte(nil), pdu...))
		response, ok := s.responses[pdu[0]]
		if !ok {
			// An unscripted request is answered as attribute not found, which ends a
			// range the way a peer would.
			response = []byte{bluetooth.ATTErrorResponse, pdu[0], 0xff, 0x00, 0x0a}
		}
		if err := writeACL(s.fd, 0x000c, response); err != nil {
			return
		}
	}
}

func socketPair() (int, int, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		return 0, 0, err
	}
	if err := unix.SetNonblock(fds[0], true); err != nil {
		unix.Close(fds[0])
		unix.Close(fds[1])
		return 0, 0, err
	}
	return fds[0], fds[1], nil
}

func TestWalkGATTSurfacesAPeerThatDemandsEncryption(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	link, peer := newScriptedPeer(t, bluetooth.DefaultATTMTU)
	peer.responses[bluetooth.ATTExchangeMTURequest] = []byte{bluetooth.ATTExchangeMTUResponse, 23, 0x00}
	peer.responses[bluetooth.ATTReadByGroupTypeRequest] = []byte{
		bluetooth.ATTErrorResponse, bluetooth.ATTReadByGroupTypeRequest, 0x01, 0x00, 0x0f,
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		peer.serve(t, ctx, 8*time.Second)
	}()
	_ = link.exchangeMTU(ctx, bluetooth.DefaultDiscoveryMTU)
	if _, _, err := walkGATT(ctx, link, GATTEnumerationOptions{Timeout: 5 * time.Second}); err == nil {
		t.Error("a peer that requires encryption must fail the enumeration rather than report an empty table")
	}
	cancel()
	<-done
}

func TestWalkGATTReportsADisconnectedPeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, server, err := socketPair()
	if err != nil {
		t.Skipf("cannot create a socket pair: %v", err)
	}
	defer unix.Close(client)
	defer unix.Close(server)
	link := &attLink{fd: client, handle: 0x000c, mtu: bluetooth.DefaultATTMTU}
	// A disconnection complete event for this handle.
	event := []byte{0x05, 0x04, 0x05, 0x0c, 0x00, 0x16}
	go func() {
		unix.Write(server, event)
	}()
	if _, err := link.request(ctx, servicePageRequestForTest()); err == nil {
		t.Error("a peer that disconnects mid-request must be reported")
	}
}

func TestWalkGATTTimesOutWhenThePeerIsSilent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, server, err := socketPair()
	if err != nil {
		t.Skipf("cannot create a socket pair: %v", err)
	}
	defer unix.Close(client)
	defer unix.Close(server)
	link := &attLink{fd: client, handle: 0x000c, mtu: bluetooth.DefaultATTMTU}
	start := time.Now()
	if _, err := link.request(ctx, servicePageRequestForTest()); err == nil {
		t.Fatal("a silent peer must produce an error, not a hang")
	}
	if waited := time.Since(start); waited > requestTimeout+2*time.Second {
		t.Errorf("the wait took %s, which is longer than the %s bound", waited, requestTimeout)
	}
}

func TestWalkGATTHonoursContextCancellation(t *testing.T) {
	client, server, err := socketPair()
	if err != nil {
		t.Skipf("cannot create a socket pair: %v", err)
	}
	defer unix.Close(client)
	defer unix.Close(server)
	link := &attLink{fd: client, handle: 0x000c, mtu: bluetooth.DefaultATTMTU}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := link.request(ctx, servicePageRequestForTest()); err == nil {
		t.Error("a cancelled context must stop the exchange")
	}
}

func TestWalkGATTRefusesAnUnsolicitedWriteRequest(t *testing.T) {
	// The exchange must not be able to send a request with no response, because
	// waiting for one would block until the timeout.
	if _, ok := attResponseOpcode(bluetooth.ATTReadByTypeRequest + 0); !ok {
		t.Fatal("sanity")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, server, err := socketPair()
	if err != nil {
		t.Skipf("cannot create a socket pair: %v", err)
	}
	defer unix.Close(client)
	defer unix.Close(server)
	link := &attLink{fd: client, handle: 0x000c, mtu: bluetooth.DefaultATTMTU}
	// 0x52 is Write Command, which a discovery walk must never send.
	if _, err := link.request(ctx, []byte{0x52, 0x01, 0x00}); err == nil {
		t.Error("an opcode with no response must be refused")
	}
}

// servicePageForTest builds a read-by-group-type response listing one service.
func servicePageForTest(start, end, uuid uint16) []byte {
	pdu := []byte{bluetooth.ATTReadByGroupTypeResponse, 0x06}
	pdu = binary.LittleEndian.AppendUint16(pdu, start)
	pdu = binary.LittleEndian.AppendUint16(pdu, end)
	return append(pdu, byte(uuid), byte(uuid>>8))
}

// characteristicPageForTest builds a read-by-type response listing one
// characteristic.
func characteristicPageForTest(declaration uint16, properties uint8, value uint16, uuid uint16) []byte {
	pdu := []byte{bluetooth.ATTReadByTypeResponse, 0x07}
	pdu = binary.LittleEndian.AppendUint16(pdu, declaration)
	pdu = append(pdu, properties)
	pdu = binary.LittleEndian.AppendUint16(pdu, value)
	return append(pdu, byte(uuid), byte(uuid>>8))
}

// findPageForTest builds a find-information response listing the given handles as
// client characteristic configuration descriptors.
func findPageForTest(handles ...uint16) []byte {
	pdu := []byte{bluetooth.ATTFindInformationResponse, 0x01}
	for _, handle := range handles {
		pdu = binary.LittleEndian.AppendUint16(pdu, handle)
		pdu = append(pdu, 0x02, 0x29)
	}
	return pdu
}

// servicePageRequestForTest builds the request a walk sends to list services.
func servicePageRequestForTest() []byte {
	request, err := bluetooth.BuildReadByGroupTypeRequest(0x0001, bluetooth.ATTMaxHandle, bluetooth.UUIDPrimaryService)
	if err != nil {
		panic(err)
	}
	return request
}
