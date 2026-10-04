package wireless

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

const (
	maxCaptureStations       = 1 << 16
	maxCaptureAuthentication = 1 << 16
	maxCaptureWEPIVs         = 1 << 20
	maxProbeNamesPerStation  = 64
	maxCaptureProbeNames     = 1 << 13
)

// CaptureInventory is the passive topology extracted from a capture.
type CaptureInventory struct {
	AccessPoints   []models.AccessPoint
	Stations       []models.Station
	Authentication []models.WirelessAuthenticationObservation
	Summary        CaptureSummary
}

// ReadPCAPAccessPoints extracts AP observations from a PCAP/PCAPNG stream.
// Prefer ReadPCAPInventory when client relationships are also needed.
func ReadPCAPAccessPoints(r io.Reader) ([]models.AccessPoint, CaptureSummary, error) {
	return ReadPCAPAccessPointsContext(context.Background(), r)
}

// ReadPCAPAccessPointsContext is ReadPCAPAccessPoints with cancellation
// checked between packet records.
func ReadPCAPAccessPointsContext(ctx context.Context, r io.Reader) ([]models.AccessPoint, CaptureSummary, error) {
	inventory, err := ReadPCAPInventoryContext(ctx, r)
	return inventory.AccessPoints, inventory.Summary, err
}

// ReadPCAPInventory streams a PCAP/PCAPNG capture and builds a bounded AP/client
// topology from beacon, probe, association, and data frame headers.
func ReadPCAPInventory(r io.Reader) (CaptureInventory, error) {
	return ReadPCAPInventoryContext(context.Background(), r)
}

// ReadPCAPInventoryContext is ReadPCAPInventory with cancellation checked
// between every packet record.
func ReadPCAPInventoryContext(ctx context.Context, r io.Reader) (CaptureInventory, error) {
	inventory := CaptureInventory{}
	byBSSID := make(map[[6]byte]models.AccessPoint)
	byStation := make(map[[6]byte]models.Station)
	probeNames := 0
	malformedElements := uint64(0)
	authSeen := make(map[string]struct{})
	malformedAuthentication := uint64(0)
	var handshakeMessages, pmkidObservations uint64
	wepIVs := make(map[[9]byte]struct{})
	wepFramesByBSSID := make(map[string]uint64)
	wepUniqueByBSSID := make(map[string]uint64)
	wepDuplicatesByBSSID := make(map[string]uint64)
	wepIVTrackingTruncated := false
	summary, err := ReadCaptureContext(ctx, r, func(record PacketRecord) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if record.FrameError != nil {
			return nil
		}
		frame := record.Frame
		if frame.Type == FrameData && frame.Protected && frame.HeaderLength >= 24 && len(record.Data) >= frame.HeaderLength+4 {
			bssid, _ := authenticationAddresses(frame)
			ok := frame.ToDS != frame.FromDS
			keyOffset := frame.HeaderLength
			if ok && record.Data[keyOffset+3]&0x20 == 0 { // legacy WEP header has no ExtIV bit
				wepFramesByBSSID[bssid]++
				var key [9]byte
				bssidMAC := frame.Address1
				if frame.FromDS {
					bssidMAC = frame.Address2
				}
				copy(key[:6], bssidMAC[:])
				copy(key[6:], record.Data[keyOffset:keyOffset+3])
				if _, exists := wepIVs[key]; !exists {
					if len(wepIVs) < maxCaptureWEPIVs {
						wepIVs[key] = struct{}{}
						wepUniqueByBSSID[bssid]++
					} else {
						wepIVTrackingTruncated = true
					}
				} else {
					wepDuplicatesByBSSID[bssid]++
				}
			}
		}
		auth, authOK, authErr := ParseAuthenticationObservation(record)
		if authErr != nil {
			malformedAuthentication++
		} else if authOK {
			handshakeMessages++
			if auth.Kind == "pmkid-observation" {
				pmkidObservations++
			}
			key := fmt.Sprintf("%s/%s/%s/%d/%s", auth.BSSID, auth.Station, auth.Message, auth.ReplayCounter, auth.PMKIDSHA256)
			if _, exists := authSeen[key]; !exists {
				if len(authSeen) >= maxCaptureAuthentication {
					return ErrCaptureLimit
				}
				authSeen[key] = struct{}{}
				inventory.Authentication = append(inventory.Authentication, auth)
			}
		}
		switch frame.Type {
		case FrameManagement:
			switch frame.Subtype {
			case 5, 8: // probe response, beacon
				if !isUnicastMAC(frame.Address3) {
					return nil
				}
				elements, err := ParseBeaconProbeResponse(record.Data)
				if err != nil {
					malformedElements++
					return nil
				}
				if _, exists := byBSSID[frame.Address3]; !exists && len(byBSSID) >= maxCaptureAccessPoints {
					return ErrCaptureLimit
				}
				upsertCaptureAP(byBSSID, frame.Address3, elements, record.Timestamp)
			case 4: // probe request
				if !isUnicastMAC(frame.Address2) {
					return nil
				}
				elements, err := ParseInformationElements(record.Data[frame.HeaderLength:])
				if err != nil {
					malformedElements++
					return nil
				}
				station, err := captureStation(byStation, frame.Address2, record.Timestamp)
				if err != nil {
					return err
				}
				if elements.SSIDPresent && elements.SSID != "" && len(station.ProbedSSIDs) < maxProbeNamesPerStation && probeNames < maxCaptureProbeNames && !containsString(station.ProbedSSIDs, elements.SSID) {
					station.ProbedSSIDs = append(station.ProbedSSIDs, elements.SSID)
					probeNames++
				}
				byStation[frame.Address2] = station
			case 0, 2: // association/reassociation request
				if !isUnicastMAC(frame.Address1) || !isUnicastMAC(frame.Address2) {
					return nil
				}
				station, err := captureStation(byStation, frame.Address2, record.Timestamp)
				if err != nil {
					return err
				}
				station.APBSSID, station.Associated = formatMAC(frame.Address1), false
				station.LastSeen = record.Timestamp
				byStation[frame.Address2] = station
			case 1, 3: // association/reassociation response
				if !isUnicastMAC(frame.Address1) || !isUnicastMAC(frame.Address2) {
					return nil
				}
				if len(record.Data) < frame.HeaderLength+6 {
					malformedElements++
					return nil
				}
				station, err := captureStation(byStation, frame.Address1, record.Timestamp)
				if err != nil {
					return err
				}
				status := binary.LittleEndian.Uint16(record.Data[frame.HeaderLength+2 : frame.HeaderLength+4])
				station.APBSSID, station.Associated = formatMAC(frame.Address2), status == 0
				station.LastSeen = record.Timestamp
				byStation[frame.Address1] = station
			case 10, 12: // disassociation/deauthentication, if unicast to a client
				if isUnicastMAC(frame.Address1) && isUnicastMAC(frame.Address2) {
					if station, ok := byStation[frame.Address1]; ok && station.APBSSID == formatMAC(frame.Address3) {
						station.Associated = false
						station.LastSeen = record.Timestamp
						byStation[frame.Address1] = station
					}
				}
			}
		case FrameData:
			var stationMAC, apMAC [6]byte
			switch {
			case frame.ToDS && !frame.FromDS:
				apMAC, stationMAC = frame.Address1, frame.Address2
			case frame.FromDS && !frame.ToDS:
				apMAC, stationMAC = frame.Address2, frame.Address1
			default:
				return nil
			}
			if !isUnicastMAC(stationMAC) || !isUnicastMAC(apMAC) {
				return nil
			}
			station, err := captureStation(byStation, stationMAC, record.Timestamp)
			if err != nil {
				return err
			}
			station.APBSSID, station.Associated = formatMAC(apMAC), true
			station.LastSeen = record.Timestamp
			byStation[stationMAC] = station
		}
		return nil
	})
	summary.Malformed += malformedElements
	summary.MalformedAuthentication = malformedAuthentication
	summary.HandshakeMessages = handshakeMessages
	summary.FourWayMessageSets = markCompleteFourWaySets(inventory.Authentication)
	summary.PMKIDObservations = pmkidObservations
	inventory.Summary = summary
	inventory.AccessPoints = make([]models.AccessPoint, 0, len(byBSSID))
	for _, ap := range byBSSID {
		inventory.AccessPoints = append(inventory.AccessPoints, ap)
	}
	for _, ap := range inventory.AccessPoints {
		isWEP := false
		isWEP = strings.EqualFold(ap.Security.Auth, "WEP") || strings.EqualFold(ap.Security.Cipher, "WEP")
		if !isWEP {
			continue
		}
		frames, unique := wepFramesByBSSID[ap.BSSID], wepUniqueByBSSID[ap.BSSID]
		if frames == 0 {
			continue
		}
		duplicates := wepDuplicatesByBSSID[ap.BSSID]
		summary.WEPEncryptedFrames += frames
		summary.WEPUniqueIVs += unique
		summary.WEPDuplicateIVs += duplicates
		summary.WEPIVTrackingTruncated = summary.WEPIVTrackingTruncated || wepIVTrackingTruncated
		inventory.Authentication = append(inventory.Authentication, models.WirelessAuthenticationObservation{
			BSSID: ap.BSSID, Kind: "wep-capture-conditions", WEPEncryptedFrames: frames,
			WEPUniqueIVs: unique, WEPDuplicateIVs: duplicates, WEPIVTrackingTruncated: wepIVTrackingTruncated,
		})
	}
	inventory.Summary = summary
	sort.Slice(inventory.AccessPoints, func(i, j int) bool { return inventory.AccessPoints[i].BSSID < inventory.AccessPoints[j].BSSID })
	inventory.Stations = make([]models.Station, 0, len(byStation))
	for _, station := range byStation {
		inventory.Stations = append(inventory.Stations, station)
	}
	sort.Slice(inventory.Stations, func(i, j int) bool { return inventory.Stations[i].MAC < inventory.Stations[j].MAC })
	ApplyAuthenticationSSIDs(inventory.Authentication, inventory.AccessPoints)
	sort.Slice(inventory.Authentication, func(i, j int) bool {
		a, b := inventory.Authentication[i], inventory.Authentication[j]
		if a.BSSID != b.BSSID {
			return a.BSSID < b.BSSID
		}
		if a.Station != b.Station {
			return a.Station < b.Station
		}
		if a.ReplayCounter != b.ReplayCounter {
			return a.ReplayCounter < b.ReplayCounter
		}
		return a.Message < b.Message
	})
	return inventory, err
}

func upsertCaptureAP(byBSSID map[[6]byte]models.AccessPoint, mac [6]byte, elements ManagementElements, timestamp time.Time) {
	// Called only after validating the unique-BSSID limit in the parser below.
	ap, exists := byBSSID[mac]
	if !exists {
		bssid := formatMAC(mac)
		ap = models.AccessPoint{BSSID: bssid, Vendor: VendorFromBSSID(bssid), Source: "pcap", FirstSeen: timestamp}
	}
	if elements.SSIDPresent && (ap.SSID == "" || ap.Hidden) {
		ap.SSID = elements.SSID
		ap.Hidden = elements.SSID == ""
	}
	if elements.Channel != 0 {
		ap.Channel = int(elements.Channel)
		if ap.Channel <= 14 {
			ap.Frequency = models.ChannelToFreq(ap.Channel)
			ap.Band = string(models.Band24GHz)
		} else {
			// Channel alone cannot distinguish 5 GHz from 6 GHz.
			ap.Band = string(models.BandUnknown)
		}
	}
	for _, flag := range elements.CapabilityFlags {
		if !containsString(ap.CapabilityFlags, flag) {
			ap.CapabilityFlags = append(ap.CapabilityFlags, flag)
		}
	}
	for _, encodedRate := range elements.SupportedRates {
		units := encodedRate & 0x7f // 500 kbit/s units; bit 7 marks a basic rate.
		if units == 0 {
			continue
		}
		rate := float32(units) / 2
		if !containsRate(ap.SupportedRatesMbps, rate) {
			ap.SupportedRatesMbps = append(ap.SupportedRatesMbps, rate)
		}
		if encodedRate&0x80 != 0 && !containsRate(ap.BasicRatesMbps, rate) {
			ap.BasicRatesMbps = append(ap.BasicRatesMbps, rate)
		}
	}
	ap.Security = securityFromManagement(elements)
	ap.LastSeen = timestamp
	byBSSID[mac] = ap
}

func containsRate(rates []float32, want float32) bool {
	for _, rate := range rates {
		if rate == want {
			return true
		}
	}
	return false
}

func captureStation(stations map[[6]byte]models.Station, mac [6]byte, timestamp time.Time) (models.Station, error) {
	if station, exists := stations[mac]; exists {
		station.LastSeen = timestamp
		return station, nil
	}
	if len(stations) >= maxCaptureStations {
		return models.Station{}, ErrCaptureLimit
	}
	return models.Station{MAC: formatMAC(mac), Source: "pcap", FirstSeen: timestamp, LastSeen: timestamp}, nil
}

func isUnicastMAC(mac [6]byte) bool {
	if mac == [6]byte{} || mac == [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff} {
		return false
	}
	return mac[0]&1 == 0
}

func securityFromManagement(elements ManagementElements) models.SecurityAdvertisement {
	if elements.RSN == nil {
		if elements.WPA {
			return models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA"}, Auth: "UNKNOWN", WPS: elements.WPS}
		}
		if elements.Privacy {
			return models.SecurityAdvertisement{
				Enabled: true, Protocols: []string{"WEP"}, Auth: "WEP", Cipher: "WEP",
				GroupCipher: "WEP", PairwiseCiphers: []string{"WEP"}, WPS: elements.WPS,
			}
		}
		return models.SecurityAdvertisement{Auth: "OPEN", WPS: elements.WPS}
	}
	rsn := elements.RSN
	protocols := []string{"WPA2"}
	if hasAKM(rsn.AKMSuites, "SAE") || hasAKM(rsn.AKMSuites, "FT-SAE") {
		protocols = []string{"WPA3"}
		if hasAKM(rsn.AKMSuites, "PSK") || hasAKM(rsn.AKMSuites, "FT-PSK") {
			protocols = append(protocols, "WPA2")
		}
	}
	if hasAKM(rsn.AKMSuites, "OWE") {
		protocols = []string{"OWE"}
	}
	pairwise := append([]string(nil), rsn.PairwiseCiphers...)
	cipher := ""
	if len(pairwise) > 0 {
		cipher = pairwise[0]
	}
	keyMgmt := strings.Join(rsn.AKMSuites, " ")
	sec := models.SecurityAdvertisement{
		Enabled: true, Protocols: protocols, Cipher: cipher,
		GroupCipher: rsn.GroupCipher, PairwiseCiphers: pairwise,
		AKMSuites: append([]string(nil), rsn.AKMSuites...), KeyMgmt: keyMgmt,
		Enterprise: hasAKM(rsn.AKMSuites, "802.1X") || hasAKM(rsn.AKMSuites, "FT-802.1X"),
		PMF:        rsn.PMFCapable, WPS: elements.WPS,
		Transition: containsString(protocols, "WPA3") && containsString(protocols, "WPA2"),
	}
	NormalizeSecurity(&sec)
	return sec
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func formatMAC(mac [6]byte) string {
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}
