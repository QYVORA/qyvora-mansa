package wireless

import (
	"reflect"
	"time"

	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// TopologyTracker incrementally identifies previously unseen APs and clients
// from live raw-frame capture. It keeps bounded state and never retains packet
// buffers. Full topology details are still produced by the offline PCAP pass.
type TopologyTracker struct {
	accessPoints map[[6]byte]models.AccessPoint
	stations     map[[6]byte]models.Station
}

// TopologyUpdate describes a meaningful change to one tracked AP or client.
// LastSeen-only refreshes are deliberately not emitted as update events.
type TopologyUpdate struct {
	AccessPoint    *models.AccessPoint
	Station        *models.Station
	AccessPointNew bool
	StationNew     bool
	RoamedFrom     string
}

// NewTopologyTracker creates a tracker with independent bounded AP/client state.
func NewTopologyTracker() *TopologyTracker {
	return &TopologyTracker{
		accessPoints: make(map[[6]byte]models.AccessPoint),
		stations:     make(map[[6]byte]models.Station),
	}
}

// Observe processes one raw capture packet. It returns an AP and/or station
// only on first discovery, so callers can emit exactly-once discovery events.
// Malformed frames are ignored; unsupported link types and oversized packets
// are returned as errors.
func (t *TopologyTracker) Observe(linkType uint32, at time.Time, packet []byte) (*models.AccessPoint, *models.Station, error) {
	update, err := t.ObserveDetailed(linkType, at, packet)
	if err != nil {
		return nil, nil, err
	}
	if update.AccessPointNew {
		return update.AccessPoint, update.StationIfNew(), nil
	}
	if update.StationNew {
		return nil, update.Station, nil
	}
	return nil, nil, nil
}

// ObserveDetailed incrementally parses a packet and returns newly discovered
// entities or material updates for known entities.
func (t *TopologyTracker) ObserveDetailed(linkType uint32, at time.Time, packet []byte) (TopologyUpdate, error) {
	if t == nil {
		return TopologyUpdate{}, nil
	}
	record, err := ParseCapturePacket(linkType, at, packet)
	if err != nil {
		return TopologyUpdate{}, err
	}
	if record.FrameError != nil {
		return TopologyUpdate{}, nil
	}
	frame := record.Frame
	update := TopologyUpdate{}
	var stationMAC [6]byte
	var apMAC [6]byte
	var associate bool

	switch frame.Type {
	case FrameManagement:
		switch frame.Subtype {
		case 5, 8: // probe response, beacon
			if isUnicastMAC(frame.Address3) {
				elements, parseErr := ParseBeaconProbeResponse(record.Data)
				if parseErr == nil {
					if _, exists := t.accessPoints[frame.Address3]; !exists && len(t.accessPoints) < maxCaptureAccessPoints {
						upsertCaptureAP(t.accessPoints, frame.Address3, elements, at)
						value := t.accessPoints[frame.Address3]
						update.AccessPoint, update.AccessPointNew = &value, true
					} else if exists {
						before := t.accessPoints[frame.Address3]
						upsertCaptureAP(t.accessPoints, frame.Address3, elements, at)
						after := t.accessPoints[frame.Address3]
						if accessPointChanged(before, after) {
							update.AccessPoint = &after
						}
					}
				}
			}
		case 4: // probe request
			if isUnicastMAC(frame.Address2) {
				stationMAC = frame.Address2
			}
		case 0, 2: // association/reassociation request
			if isUnicastMAC(frame.Address1) && isUnicastMAC(frame.Address2) {
				stationMAC, apMAC = frame.Address2, frame.Address1
			}
		case 1, 3: // association/reassociation response
			if isUnicastMAC(frame.Address1) && isUnicastMAC(frame.Address2) && len(record.Data) >= frame.HeaderLength+6 {
				stationMAC, apMAC = frame.Address1, frame.Address2
				associate = record.Data[frame.HeaderLength+2] == 0 && record.Data[frame.HeaderLength+3] == 0
			}
		case 10, 12: // disassociation/deauthentication of a known client
			if isUnicastMAC(frame.Address1) {
				if station, exists := t.stations[frame.Address1]; exists && station.APBSSID == formatMAC(frame.Address3) {
					before := station
					station.Associated = false
					station.LastSeen = at
					t.stations[frame.Address1] = station
					if stationChanged(before, station) {
						value := station
						update.Station = &value
					}
				}
			}
		}
	case FrameData:
		switch {
		case frame.ToDS && !frame.FromDS:
			apMAC, stationMAC, associate = frame.Address1, frame.Address2, true
		case frame.FromDS && !frame.ToDS:
			apMAC, stationMAC, associate = frame.Address2, frame.Address1, true
		}
	}

	var beforeStation models.Station
	var stationExisted bool
	if isUnicastMAC(stationMAC) {
		beforeStation, stationExisted = t.stations[stationMAC]
		if len(t.stations) < maxCaptureStations || stationExisted {
			station, stationErr := captureStation(t.stations, stationMAC, at)
			if stationErr == nil {
				if isUnicastMAC(apMAC) {
					station.APBSSID = formatMAC(apMAC)
					station.Associated = associate
				}
				t.stations[stationMAC] = station
				if !stationExisted {
					value := station
					update.Station, update.StationNew = &value, true
				} else if stationChanged(beforeStation, station) {
					value := station
					update.Station = &value
					if beforeStation.APBSSID != "" && station.APBSSID != "" && beforeStation.APBSSID != station.APBSSID {
						update.RoamedFrom = beforeStation.APBSSID
					}
				}
			}
		}
	}
	return update, nil
}

func (u TopologyUpdate) StationIfNew() *models.Station {
	if u.StationNew {
		return u.Station
	}
	return nil
}

func accessPointChanged(a, b models.AccessPoint) bool {
	return a.SSID != b.SSID || a.Channel != b.Channel || a.Frequency != b.Frequency || a.Band != b.Band || a.Vendor != b.Vendor || a.Hidden != b.Hidden || !reflect.DeepEqual(a.Security, b.Security) || a.Capabilities != b.Capabilities || !equalSlices(a.SupportedRatesMbps, b.SupportedRatesMbps) || !equalSlices(a.BasicRatesMbps, b.BasicRatesMbps)
}

func stationChanged(a, b models.Station) bool {
	return a.APBSSID != b.APBSSID || a.Associated != b.Associated || a.Signal != b.Signal || !equalSlices(a.ProbedSSIDs, b.ProbedSSIDs)
}

func equalSlices[T comparable](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
