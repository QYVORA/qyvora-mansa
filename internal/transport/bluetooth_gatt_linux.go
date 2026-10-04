//go:build linux

package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/QYVORA/qyvora-mansa/internal/bluetooth"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// HCI opcodes and constants needed to enumerate a peer's GATT table.
//
// The attribute protocol runs on the fixed L2CAP channel the controller assigns
// for ATT, so no L2CAP signalling is needed on the host: every ATT PDU travels in
// an HCI ACL data packet addressed to that channel.
const (
	hciOCFLECreateConnection    = 0x000d
	hciOCFDisconnect            = 0x0006
	hciACLDataPacket            = 0x02
	hciACLStartFlushable        = 0x02
	hciLEMetaConnectionComplete = 0x01
	l2capCIDATT                 = 0x0004
	l2capLengthBytes            = 2
	l2capCIDBytes               = 2
	// maxACLFragmentPayload is the largest L2CAP payload that always fits an ACL
	// data packet. It bounds fragmentation when a peer claims an MTU the link
	// layer cannot carry.
	maxACLFragmentPayload = 251
	// requestTimeout bounds one ATT request/response exchange so a peer that
	// never answers cannot hold the command open.
	requestTimeout = 5 * time.Second
	// LE connection parameters used for a read-only enumeration: a supervision
	// timeout of 5 s and a connection interval of 50 ms.
	leSupervisionTimeout = 0x00a8
	leConnectionInterval = 0x0028
)

// GATTEnumerationOptions bounds one live enumeration.
type GATTEnumerationOptions struct {
	// Timeout bounds the whole enumeration.
	Timeout time.Duration
	// MTU is the ATT receive buffer requested from the peer.
	MTU uint16
	// DiscoverDescriptors requests descriptor discovery in addition to services
	// and characteristics.
	DiscoverDescriptors bool
	// MaxServices, MaxCharacteristics, and MaxDescriptors override the package
	// bounds when lower, so a caller can cap a walk further.
	MaxServices        int
	MaxCharacteristics int
	MaxDescriptors     int
}

// GATTEnumerationStats reports what one enumeration observed.
type GATTEnumerationStats struct {
	Address         string                          `json:"address"`
	Services        int                             `json:"services"`
	Characteristics int                             `json:"characteristics"`
	Descriptors     int                             `json:"descriptors"`
	Requests        int                             `json:"requests"`
	MTU             uint16                          `json:"att_mtu"`
	Truncated       bool                            `json:"truncated"`
	Database        models.GATTDatabase             `json:"database"`
	Controller      *models.BluetoothControllerInfo `json:"controller,omitempty"`
}

// GATTEnumerationProvider enumerates a peer's GATT table.
type GATTEnumerationProvider interface {
	EnumerateGATT(ctx context.Context, adapter, address string, options GATTEnumerationOptions) (GATTEnumerationStats, error)
}

// EnumerateGATT discovers a peer's services, characteristics, and descriptors.
//
// The sequence is: open the adapter, create a link, exchange MTUs, walk the
// service table, walk each service's characteristics, optionally walk each
// characteristic's descriptors, then disconnect. Only read-only ATT requests are
// sent; the enumeration writes no attribute and subscribes to nothing, so a peer
// that requires pairing simply answers with an error and the walk ends there.
func (b *LinuxBackend) EnumerateGATT(ctx context.Context, adapterName, address string, options GATTEnumerationOptions) (stats GATTEnumerationStats, resultErr error) {
	if address == "" {
		return stats, errors.New("a peer Bluetooth address is required for GATT enumeration")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if options.Timeout <= 0 {
		options.Timeout = bluetooth.DefaultDiscoveryTimeout
	}
	if options.MTU == 0 {
		options.MTU = bluetooth.DefaultDiscoveryMTU
	}
	if options.MTU > maxACLFragmentPayload {
		// Asking for more than the controller's largest ACL data payload would
		// have the peer fragment its responses into packets this client cannot
		// reassemble, so the request is held at what the link can carry.
		options.MTU = maxACLFragmentPayload
	}
	peer, err := parseBluetoothAddress(address)
	if err != nil {
		return stats, err
	}
	index, err := parseHCIIndex(adapterName)
	if err != nil {
		return stats, err
	}
	fd, err := unix.Socket(unix.AF_BLUETOOTH, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.BTPROTO_HCI)
	if err != nil {
		return stats, fmt.Errorf("open HCI socket (CAP_NET_RAW may be required): %w", err)
	}
	defer unix.Close(fd)
	if err = unix.Bind(fd, &unix.SockaddrHCI{Dev: uint16(index), Channel: unix.HCI_CHANNEL_RAW}); err != nil {
		return stats, fmt.Errorf("bind HCI adapter %s: %w", adapterName, err)
	}
	if err = unix.SetNonblock(fd, true); err != nil {
		return stats, fmt.Errorf("set HCI socket non-blocking: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()

	link := &attLink{fd: fd, peer: peer, mtu: bluetooth.DefaultATTMTU}
	if link.handle, err = createLEConnection(ctx, fd, peer, options.Timeout); err != nil {
		return stats, err
	}
	// A link is torn down on every exit path, so a cancelled or failed walk does
	// not leave the peer with a dangling connection.
	defer func() {
		disconnectErr := disconnectLink(fd, link.handle)
		if resultErr == nil && disconnectErr != nil {
			resultErr = disconnectErr
		}
	}()

	if err = link.exchangeMTU(ctx, options.MTU); err != nil {
		return stats, err
	}
	stats.MTU = link.mtu

	database, discoveryStats, err := walkGATT(ctx, link, options)
	stats.Database = database
	stats.Services = discoveryStats.Services
	stats.Characteristics = discoveryStats.Characteristics
	stats.Descriptors = discoveryStats.Descriptors
	stats.Requests = discoveryStats.Requests
	stats.Truncated = discoveryStats.Truncated
	stats.Address = address
	return stats, err
}

// walkGATT performs the read-only ATT requests that build the database. It is
// separated from the HCI plumbing so the walk can be exercised against a scripted
// peer.
func walkGATT(ctx context.Context, link *attLink, options GATTEnumerationOptions) (models.GATTDatabase, bluetooth.DiscoveryStats, error) {
	discoverer := bluetooth.NewDiscovererWithLimits(link.peer.String(), bluetooth.DiscoveryLimits{
		Services: options.MaxServices, Characteristics: options.MaxCharacteristics,
		Descriptors: options.MaxDescriptors,
	})

	// Primary and secondary services are walked separately because they share a
	// declaration type space only by name, and conflating them would report a
	// secondary service as primary.
	for _, serviceType := range []uint16{bluetooth.UUIDPrimaryService, bluetooth.UUIDSecondaryService} {
		if err := ctx.Err(); err != nil {
			return models.GATTDatabase{}, bluetooth.DiscoveryStats{}, err
		}
		if err := walkServiceType(ctx, link, discoverer, serviceType, options); err != nil {
			return models.GATTDatabase{}, bluetooth.DiscoveryStats{}, err
		}
	}
	// The snapshot must exist before characteristics can be walked, because each
	// characteristic's descriptors are bounded by its service's handle range.
	database, _ := discoverer.Database()
	if err := walkCharacteristics(ctx, link, discoverer, &database, options); err != nil {
		// The statistics are still reported on a failure so a caller can see how far
		// the walk got rather than only that it stopped.
		_, stats := discoverer.Database()
		return database, stats, err
	}
	// Rebuilt here because the walks above recorded characteristics and descriptors
	// after the snapshot was taken, and the statistics must describe the snapshot
	// that is returned.
	database, stats := discoverer.Database()
	return database, stats, nil
}

// stopped reports whether an error ends the walk without failing the enumeration.
//
// A discovery bound is a refusal to keep going, not evidence of a faulty peer, so
// the partial table is returned with its truncation flag set. Every other error,
// including a peer that demands encryption, fails the enumeration.
func stopped(err error) bool {
	return errors.Is(err, bluetooth.ErrDiscoveryLimit)
}

// walkServiceType pages through one service declaration type until the peer
// reports the range complete.
func walkServiceType(ctx context.Context, link *attLink, discoverer *bluetooth.Discoverer, serviceType uint16, options GATTEnumerationOptions) error {
	start := uint16(0x0001)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if options.MaxServices > 0 && discoverer.Services(serviceType) >= options.MaxServices {
			return nil
		}
		request, err := bluetooth.BuildReadByGroupTypeRequest(start, bluetooth.ATTMaxHandle, serviceType)
		if err != nil {
			return err
		}
		pdu, err := link.request(ctx, request)
		if err != nil {
			return err
		}
		nextStart, done, err := discoverer.RecordServices(serviceType, pdu)
		if stopped(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		if nextStart <= start {
			return fmt.Errorf("the peer returned service handle 0x%04x after 0x%04x without advancing", nextStart, start)
		}
		start = nextStart
	}
}

// walkCharacteristics walks each discovered service's characteristics and,
// optionally, each characteristic's descriptors. Both walks resume from the
// handle after the last attribute the peer described.
func walkCharacteristics(ctx context.Context, link *attLink, discoverer *bluetooth.Discoverer, database *models.GATTDatabase, options GATTEnumerationOptions) error {
	for serviceIndex := range database.Services {
		service := &database.Services[serviceIndex]
		// The declaration attribute itself is the first entry, so the walk starts
		// after it and the end handle bounds the range to this service.
		start := service.StartHandle + 1
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			request, err := bluetooth.BuildReadByTypeRequest(start, service.EndHandle, bluetooth.UUIDCharacteristicDeclaration)
			if err != nil {
				return err
			}
			pdu, err := link.request(ctx, request)
			if err != nil {
				return err
			}
			nextStart, done, err := discoverer.RecordCharacteristics(pdu)
			if stopped(err) {
				return nil
			}
			if err != nil {
				return err
			}
			if done {
				break
			}
			if nextStart <= start {
				return fmt.Errorf("the peer returned characteristic handle 0x%04x after 0x%04x without advancing", nextStart, start)
			}
			start = nextStart
		}
	}
	if !options.DiscoverDescriptors || discoverer.Truncated() {
		return nil
	}
	// The database must be rebuilt so the newly recorded characteristics exist
	// before descriptors are attached to them.
	*database, _ = discoverer.Database()
	return walkDescriptors(ctx, link, discoverer, database, options)
}

func walkDescriptors(ctx context.Context, link *attLink, discoverer *bluetooth.Discoverer, database *models.GATTDatabase, options GATTEnumerationOptions) error {
	total := 0
	for serviceIndex := range database.Services {
		service := &database.Services[serviceIndex]
		for characteristicIndex := range service.Characteristics {
			characteristic := &service.Characteristics[characteristicIndex]
			// Descriptors follow the value attribute, so the walk starts at the
			// handle after it and ends just before the next characteristic's
			// declaration, whose handle bounds this characteristic's descriptor
			// range.
			start := characteristic.Handle + 1
			end := service.EndHandle
			if characteristicIndex+1 < len(service.Characteristics) {
				end = nextDeclarationHandle(service, characteristicIndex) - 1
			}
			for {
				if err := ctx.Err(); err != nil {
					return err
				}
				if options.MaxDescriptors > 0 && total >= options.MaxDescriptors {
					return nil
				}
				if start > end {
					break
				}
				request, err := bluetooth.BuildFindInformationRequest(start, end)
				if err != nil {
					return err
				}
				pdu, err := link.request(ctx, request)
				if err != nil {
					return err
				}
				if attErr, isError, err := bluetooth.ParseErrorResponse(pdu); isError {
					if err != nil {
						return err
					}
					// A peer that will not describe a range ends the walk for it.
					if attErr.ErrorCode == 0x0a || attErr.ErrorCode == 0x04 {
						break
					}
					return attErr
				}
				nextStart, _, err := discoverer.RecordAttributeRange(pdu, options.MaxDescriptors)
				if stopped(err) {
					return nil
				}
				if err != nil {
					return err
				}
				if nextStart <= start {
					break
				}
				start = nextStart
				total++
			}
		}
	}
	*database, _ = discoverer.Database()
	return nil
}

// nextDeclarationHandle returns the declaration handle of the characteristic
// after the given index, which bounds the descriptor range of the current one.
func nextDeclarationHandle(service *models.GATTService, index int) uint16 {
	if index+1 >= len(service.Characteristics) {
		return service.EndHandle
	}
	return service.Characteristics[index+1].DeclarationHandle
}

// attLink carries ATT PDUs over the fixed L2CAP channel of one LE link.
type attLink struct {
	fd     int
	peer   *bluetoothAddress
	handle uint16
	mtu    uint16
}

// request sends one ATT PDU and waits for the matching response. The wait is
// bounded, and any ACL traffic that is not an ATT response is ignored so link
// layer noise cannot desynchronize the exchange.
func (l *attLink) request(ctx context.Context, pdu []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(requestTimeout)
	for _, fragment := range fragmentPDUs(pdu, l.mtu) {
		if err := writeACL(l.fd, l.handle, fragment); err != nil {
			return nil, err
		}
	}
	opcode := pdu[0]
	responseOpcode, expectsResponse := attResponseOpcode(opcode)
	if !expectsResponse {
		return nil, fmt.Errorf("ATT opcode 0x%02x has no response to wait for", opcode)
	}
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		event, err := readHCIEvent(l.fd)
		if err != nil {
			if isRetryableSocketError(err) {
				sleepBriefly(ctx)
				continue
			}
			return nil, err
		}
		if event[1] != hciACLDataPacket {
			// Disconnection while waiting is reported rather than ignored, so a
			// peer that drops the link is not mistaken for a silent one.
			if event[1] == hciEventDisconnection && len(event) >= 5 && binary.LittleEndian.Uint16(event[3:5]) == l.handle {
				return nil, fmt.Errorf("the peer disconnected while a request was outstanding")
			}
			continue
		}
		if !isACLPacket(event) {
			continue
		}
		response, err := parseACLPayload(event, l.handle, l2capCIDATT)
		if err != nil || response == nil {
			continue
		}
		if len(response) == 0 {
			continue
		}
		// A response is either the response paired with this request or an error
		// response naming the request opcode.
		if response[0] == responseOpcode {
			return response, nil
		}
		if response[0] == bluetooth.ATTErrorResponse {
			if _, _, err := bluetooth.ParseErrorResponse(response); err != nil {
				return nil, err
			}
			return response, nil
		}
	}
	return nil, fmt.Errorf("timed out waiting for an ATT response to opcode 0x%02x", opcode)
}

// exchangeMTU negotiates the ATT MTU. A peer that does not answer keeps the
// default, which is the safe value.
func (l *attLink) exchangeMTU(ctx context.Context, clientMTU uint16) error {
	request, err := bluetooth.BuildExchangeMTURequest(clientMTU)
	if err != nil {
		return err
	}
	pdu, err := l.request(ctx, request)
	if err != nil {
		return err
	}
	mtu, err := bluetooth.ParseExchangeMTUResponse(pdu)
	if err != nil {
		return err
	}
	l.mtu = mtu
	return nil
}

// attResponseOpcode returns the response opcode paired with a request opcode.
//
// Every ATT request that has a response is answered by the next opcode value, so
// the pairing is derived rather than written out per opcode. A request with no
// response, such as Write Command, reports false because waiting for one would
// block until the timeout.
func attResponseOpcode(request byte) (response byte, ok bool) {
	switch request {
	case bluetooth.ATTExchangeMTURequest, bluetooth.ATTFindInformationRequest,
		bluetooth.ATTReadByTypeRequest, bluetooth.ATTReadByGroupTypeRequest:
		return request + 1, true
	}
	return 0, false
}

// fragmentPDUs splits an ATT PDU into ACL payloads that fit the negotiated MTU.
func fragmentPDUs(pdu []byte, mtu uint16) [][]byte {
	// An ATT PDU travels in an L2CAP frame in an ACL data packet, so the usable
	// payload is the MTU less the two headers. The bound is the negotiated MTU and
	// not the controller's largest ACL payload: sending more than the peer asked
	// for would be a protocol violation even if the link could carry it.
	capacity := int(mtu) - aclHeaderBytes - l2capLengthBytes - l2capCIDBytes
	if capacity < 1 {
		capacity = 1
	}
	if capacity >= len(pdu) {
		return [][]byte{pdu}
	}
	var fragments [][]byte
	for offset := 0; offset < len(pdu); offset += capacity {
		end := offset + capacity
		if end > len(pdu) {
			end = len(pdu)
		}
		fragments = append(fragments, pdu[offset:end])
	}
	return fragments
}

// writeACL sends one ACL data packet carrying an L2CAP frame for a handle.
func writeACL(fd int, handle uint16, payload []byte) error {
	packet := make([]byte, 4+l2capLengthBytes+l2capCIDBytes+len(payload))
	binary.LittleEndian.PutUint16(packet[0:2], handle)
	dataLen := uint16(l2capCIDBytes + 2 + len(payload)) // l2cap CID(2)+len(2)+payload? l2capLen is 2 bytes + CID is 2 bytes + payload = 4+len(payload). Yes.
	binary.LittleEndian.PutUint16(packet[2:4], dataLen)
	binary.LittleEndian.PutUint16(packet[4:6], uint16(l2capCIDBytes+len(payload)))
	binary.LittleEndian.PutUint16(packet[6:8], l2capCIDATT)
	copy(packet[8:], payload)
	if _, err := unix.Write(fd, packet); err != nil {
		return fmt.Errorf("send ACL data: %w", err)
	}
	return nil
}

// parseACL extracts the L2CAP payload for one channel of one handle, or reports
// nil when the packet belongs to another channel or another link.
func parseACL(event []byte, handle uint16, cid uint16) ([]byte, error) {
	if len(event) < 1+aclHeaderBytes {
		return nil, errors.New("ACL data event is shorter than its header")
	}
	if binary.LittleEndian.Uint16(event[1:3]) != handle {
		return nil, nil
	}
	payload := event[1+aclHeaderBytes:]
	if len(payload) < l2capLengthBytes+l2capCIDBytes {
		return nil, errors.New("ACL payload is shorter than an L2CAP header")
	}
	length := int(binary.LittleEndian.Uint16(payload[0:2]))
	channel := binary.LittleEndian.Uint16(payload[2:4])
	if channel != cid {
		return nil, nil
	}
	if length < l2capCIDBytes || 4+length > len(payload) {
		return nil, fmt.Errorf("L2CAP length %d does not match the %d-byte packet", length, len(payload))
	}
	return payload[4 : 4+length], nil
}

// readHCIEvent waits for one HCI packet, polling the non-blocking socket.
func readHCIEvent(fd int) ([]byte, error) {
	buf := make([]byte, 4096)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return nil, err
	}
	if n < 2 {
		return nil, errors.New("HCI packet is shorter than its header")
	}
	return buf[:n], nil
}

// createLEConnection establishes a link to a peer and returns its handle.
//
// The command is written here and the events are pumped locally rather than
// through sendHCICommand, because the controller answers a connection request
// with a command status and then, separately, with an LE Connection Complete
// event. A helper that stopped at the status event could consume the completion
// before the caller saw it.
func createLEConnection(ctx context.Context, fd int, peer *bluetoothAddress, timeout time.Duration) (uint16, error) {
	opcode := uint16(hciOGFLEControl)<<10 | hciOCFLECreateConnection
	params := make([]byte, 0, 25)
	params = append(params, 0x00, 0x60, 0x00, 0x30) // scan interval and window in 0.625 ms units
	params = append(params, 0x00, 0x00)             // initiator filter policy: no whitelist
	params = append(params, peer.Bytes()...)
	params = append(params, 0x00) // address type: public
	params = append(params, 0x00) // role: central
	params = append(params, 0x00, 0x00, 0x00)
	params = append(params, byte(leSupervisionTimeout), byte(leSupervisionTimeout>>8))
	params = append(params, byte(leConnectionInterval), byte(leConnectionInterval>>8))
	packet := make([]byte, 4+len(params))
	packet[0] = hciCommandPacket
	binary.LittleEndian.PutUint16(packet[1:3], opcode)
	packet[3] = byte(len(params))
	copy(packet[4:], params)
	if _, err := unix.Write(fd, packet); err != nil {
		return 0, fmt.Errorf("create LE connection to %s: %w", peer, err)
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		event, err := readHCIEvent(fd)
		if err != nil {
			if isRetryableSocketError(err) {
				sleepBriefly(ctx)
				continue
			}
			return 0, err
		}
		switch event[1] {
		case hciEventCommandStatus:
			if op, status, ok := parseCommandStatus(event); ok && op == opcode {
				if status != 0x00 {
					return 0, fmt.Errorf("the controller rejected the connection request to %s (status 0x%02x)", peer, status)
				}
				continue
			}
		case hciEventLEMeta:
			// LE Connection Complete is subevent 0x01. The status byte precedes the
			// connection handle in this layout.
			if len(event) < 13 || event[3] != hciLEMetaConnectionComplete {
				continue
			}
			if event[11] != 0x00 {
				return 0, fmt.Errorf("the controller could not connect to %s (LE status 0x%02x)", peer, event[11])
			}
			return binary.LittleEndian.Uint16(event[12:14]), nil
		}
	}
	return 0, fmt.Errorf("timed out connecting to %s", peer)
}

// isRetryableSocketError reports whether a non-blocking socket error only means
// no packet has arrived yet.

// sleepBriefly yields between polls so a wait loop does not saturate a core while
// a controller decides.
func sleepBriefly(ctx context.Context) {
	timer := time.NewTimer(time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

// disconnectLink tears down a link so the peer is not left connected.
func disconnectLink(fd int, handle uint16) error {
	params := make([]byte, 3)
	binary.LittleEndian.PutUint16(params[0:2], handle)
	params[2] = 0x13 // reason: remote user terminated the connection
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := sendHCICommandForData(fd, ctx, hciOGFLinkControl, hciOCFDisconnect, params); err != nil {
		return fmt.Errorf("disconnect handle 0x%04x: %w", handle, err)
	}
	return nil
}

// bluetoothAddress is a parsed peer address.
type bluetoothAddress [6]byte

// parseBluetoothAddress accepts the colon-separated form the adapter inventory
// prints and rejects anything else rather than guessing an address.
func parseBluetoothAddress(value string) (*bluetoothAddress, error) {
	var parsed bluetoothAddress
	fields := strings.Split(strings.TrimSpace(value), ":")
	if len(fields) != len(parsed) {
		return nil, fmt.Errorf("%q is not a colon-separated six-byte Bluetooth address", value)
	}
	for i, field := range fields {
		if len(field) != 2 {
			return nil, fmt.Errorf("%q is not a colon-separated six-byte Bluetooth address", value)
		}
		octet, err := strconv.ParseUint(field, 16, 8)
		if err != nil {
			return nil, fmt.Errorf("%q is not a colon-separated six-byte Bluetooth address", value)
		}
		parsed[i] = byte(octet)
	}
	return &parsed, nil
}

// Bytes returns the address in little-endian order, which is the layout HCI
// LE Connection Create expects. A six-byte Bluetooth address is transmitted
// least-significant octet first.
func (a *bluetoothAddress) Bytes() []byte {
	reversed := make([]byte, len(a))
	for i := range a {
		reversed[i] = a[len(a)-1-i]
	}
	return reversed
}

// String renders the address in the conventional most-significant-first order.
func (a *bluetoothAddress) String() string {
	parts := make([]string, len(a))
	for i, octet := range a {
		parts[i] = fmt.Sprintf("%02X", octet)
	}
	return strings.Join(parts, ":")
}
