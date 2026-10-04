package wireless

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/QYVORA/qyvora-mansa/internal/wpa"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

const (
	eapolPacketTypeKey = 3
	eapolFixedKeyBody  = 95
)

var llcEAPOL = []byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e}

// ParseAuthenticationObservation extracts one WPA/WPA2 EAPOL-Key message or
// PMKID KDE observation from an unprotected 802.11 data frame. It reports
// metadata only and never claims that a handshake is complete or crackable.
func ParseAuthenticationObservation(record PacketRecord) (models.WirelessAuthenticationObservation, bool, error) {
	frame := record.Frame
	if frame.Type != FrameData || frame.Protected || frame.HeaderLength < 24 || len(record.Data) < frame.HeaderLength+len(llcEAPOL)+4 {
		return models.WirelessAuthenticationObservation{}, false, nil
	}
	payload := record.Data[frame.HeaderLength:]
	for i, b := range llcEAPOL {
		if payload[i] != b {
			return models.WirelessAuthenticationObservation{}, false, nil
		}
	}
	eapol := payload[len(llcEAPOL):]
	if eapol[1] != eapolPacketTypeKey {
		return models.WirelessAuthenticationObservation{}, false, nil
	}
	bodyLength := int(binary.BigEndian.Uint16(eapol[2:4]))
	if bodyLength < eapolFixedKeyBody || bodyLength > len(eapol)-4 {
		return models.WirelessAuthenticationObservation{}, false, fmt.Errorf("invalid EAPOL-Key body length %d", bodyLength)
	}
	body := eapol[4 : 4+bodyLength]
	keyInfo := binary.BigEndian.Uint16(body[1:3])
	if keyInfo&(1<<3) == 0 {
		return models.WirelessAuthenticationObservation{}, false, nil
	}
	message := classifyEAPOLKey(keyInfo)
	if message == "" {
		return models.WirelessAuthenticationObservation{}, false, nil
	}
	bssid, station := authenticationAddresses(frame)
	if bssid == "" || station == "" {
		return models.WirelessAuthenticationObservation{}, false, nil
	}
	observation := models.WirelessAuthenticationObservation{BSSID: bssid, Station: station, Kind: "handshake-message", Message: message, ReplayCounter: wpa.ReplayCounter(body), DescriptorType: body[0], ObservedAt: record.Timestamp}
	// The layouts are derived from the observed body so an unsupported suite is
	// reported instead of being read at a guessed offset. More than one layout
	// is possible when the frame does not disambiguate the integrity code size.
	layouts, err := wpa.DescribeBody(body)
	if err != nil {
		return models.WirelessAuthenticationObservation{}, false, err
	}
	// Key data cannot vary between the candidate layouts, because every layout
	// was accepted only when its key data reached the end of the body.
	dataLength := layouts[0].KeyDataLength
	keyData := wpa.KeyData(body, layouts[0])
	if keyInfo&(1<<12) == 0 {
		if pmkid, ok, err := findPMKID(keyData); err != nil {
			return models.WirelessAuthenticationObservation{}, false, err
		} else if ok {
			digest := sha256.Sum256(pmkid)
			observation.Kind = "pmkid-observation"
			observation.PMKIDSHA256 = hex.EncodeToString(digest[:])
		}
	}
	if verification, ok := buildEAPOLVerification(bssid, message, keyInfo, body, layouts, eapol, keyData, dataLength); ok {
		observation.Verification = verification
	}
	return observation, true, nil
}

func classifyEAPOLKey(info uint16) string {
	ack := info&(1<<7) != 0
	mic := info&(1<<8) != 0
	install := info&(1<<6) != 0
	secure := info&(1<<9) != 0
	switch {
	case ack && !mic:
		return "M1"
	case !ack && mic && !secure:
		return "M2"
	case ack && mic && install:
		return "M3"
	case !ack && mic && secure:
		return "M4"
	default:
		return ""
	}
}
func authenticationAddresses(frame FrameInfo) (string, string) {
	switch {
	case frame.ToDS && !frame.FromDS:
		return formatMAC(frame.Address1), formatMAC(frame.Address2)
	case frame.FromDS && !frame.ToDS:
		return formatMAC(frame.Address2), formatMAC(frame.Address1)
	default:
		return "", ""
	}
}

// buildEAPOLVerification extracts the public material needed to recompute this
// message integrity code from a candidate pairwise master key. It reports false
// for a message that carries no integrity code, which is an M1: its integrity
// code is produced by the supplicant later and it instead contributes the
// supplicant nonce a verifier needs to derive the pairwise temporal key.
//
// The SSID is not known while a frame is parsed, so a caller that has read the
// beacons in the same capture fills in SSID afterwards with
// ApplyAuthenticationSSIDs.
func buildEAPOLVerification(bssid, message string, keyInfo uint16, body []byte, layouts []wpa.BodyLayout, eapol, keyData []byte, dataLength int) (*models.EAPOLKeyVerification, bool) {
	verification := &models.EAPOLKeyVerification{
		Message:       message,
		KeyInfo:       keyInfo,
		BSSID:         bssid,
		ReplayCounter: wpa.ReplayCounter(body),
		ANonce:        hex.EncodeToString(wpa.ANonce(body)),
		KeyIV:         hex.EncodeToString(wpa.KeyIV(body)),
		SessionKeyID:  sessionKeyID(keyData, dataLength),
		CapturedEAPOL: hex.EncodeToString(eapol[:4+len(body)]),
	}
	// Only an M1 carries the supplicant nonce that derives the pairwise temporal
	// key. Later messages leave the field zeroed, so reporting it for them would
	// hand a verifier a nonce that was never transmitted.
	if message == "M1" {
		if snonce := wpa.SNonce(body); snonce != nil && !allZero(snonce) {
			verification.SNonce = hex.EncodeToString(snonce)
			verification.SNonceValid = true
		}
	}
	// An M1 has no integrity code of its own, so it carries only the nonce.
	if keyInfo&(1<<8) == 0 {
		return verification, true
	}
	for _, layout := range layouts {
		verification.Candidates = append(verification.Candidates, models.EAPOLKeyCandidate{
			MICLength: layout.MICLength,
			MIC:       hex.EncodeToString(wpa.MIC(body, layout)),
		})
	}
	if verification.ANonce == "" || len(verification.Candidates) == 0 {
		return nil, false
	}
	if pmkid, ok := rawPMKID(keyData, dataLength); ok {
		verification.PMKID = pmkid
	}
	return verification, true
}

// allZero reports whether every byte is zero, which is how an unset EAPOL-Key
// nonce field appears on the wire.
func allZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}

// sessionKeyID returns the key data session key identifier in hexadecimal, or an
// empty string when the message carries no session key identifier element.
func sessionKeyID(keyData []byte, dataLength int) string {
	const sessionKeyIDLength = 32
	if dataLength != sessionKeyIDLength {
		return ""
	}
	selector := binary.BigEndian.Uint16(keyData[:2])
	// Selector 0 is the temporal key session key identifier and 1 is the PMKID.
	if selector != 0 {
		return ""
	}
	return hex.EncodeToString(keyData[2:])
}

// rawPMKID returns the master key identifier from a PMKID key data element. A
// PMKID is itself a master key, so a capture that carries one can be verified
// without a passphrase.
func rawPMKID(keyData []byte, dataLength int) (string, bool) {
	const pmkidElementLength = 16 + 16 + 2
	if dataLength != pmkidElementLength {
		return "", false
	}
	if binary.BigEndian.Uint16(keyData[:2]) != 1 {
		return "", false
	}
	return hex.EncodeToString(keyData[2:18]), true
}

// ApplyAuthenticationSSIDs fills in the SSID of every verification observation
// from the access points observed in the same capture. An observation whose
// BSSID was never seen advertising a name keeps an empty SSID, which a verifier
// must treat as unusable rather than as a blank network name.
func ApplyAuthenticationSSIDs(observations []models.WirelessAuthenticationObservation, accessPoints []models.AccessPoint) {
	if len(accessPoints) == 0 {
		return
	}
	ssids := make(map[string]string, len(accessPoints))
	for _, accessPoint := range accessPoints {
		if accessPoint.SSID != "" {
			ssids[accessPoint.BSSID] = accessPoint.SSID
		}
	}
	for i := range observations {
		verification := observations[i].Verification
		if verification == nil {
			continue
		}
		if ssid, ok := ssids[verification.BSSID]; ok {
			verification.SSID = ssid
		}
	}
}

// markCompleteFourWaySets marks captured observations when a BSSID/station
// pair contains M1/M2 at one replay counter and M3/M4 at a later counter. It
// describes observed metadata only; it does not validate MICs or recover keys.
func markCompleteFourWaySets(observations []models.WirelessAuthenticationObservation) uint64 {
	type pair struct{ bssid, station string }
	type counters struct{ m1, m2, m3, m4 map[uint64]struct{} }
	byPair := make(map[pair]*counters)
	for _, observation := range observations {
		if observation.Kind != "handshake-message" {
			continue
		}
		key := pair{observation.BSSID, observation.Station}
		set := byPair[key]
		if set == nil {
			set = &counters{m1: map[uint64]struct{}{}, m2: map[uint64]struct{}{}, m3: map[uint64]struct{}{}, m4: map[uint64]struct{}{}}
			byPair[key] = set
		}
		var target map[uint64]struct{}
		switch observation.Message {
		case "M1":
			target = set.m1
		case "M2":
			target = set.m2
		case "M3":
			target = set.m3
		case "M4":
			target = set.m4
		}
		if target != nil {
			target[observation.ReplayCounter] = struct{}{}
		}
	}
	type replayPair struct{ first, later uint64 }
	complete := make(map[pair]replayPair)
	for key, set := range byPair {
		firstCounter := ^uint64(0)
		for first := range set.m1 {
			if _, ok := set.m2[first]; ok && first < firstCounter {
				firstCounter = first
			}
		}
		if firstCounter == ^uint64(0) {
			continue
		}
		laterCounter := ^uint64(0)
		for later := range set.m3 {
			if later > firstCounter && later < laterCounter {
				if _, ok := set.m4[later]; ok {
					laterCounter = later
				}
			}
		}
		if laterCounter != ^uint64(0) {
			complete[key] = replayPair{firstCounter, laterCounter}
		}
	}
	for i := range observations {
		observation := &observations[i]
		set, ok := complete[pair{observation.BSSID, observation.Station}]
		if !ok {
			continue
		}
		if ((observation.Message == "M1" || observation.Message == "M2") && observation.ReplayCounter == set.first) ||
			((observation.Message == "M3" || observation.Message == "M4") && observation.ReplayCounter == set.later) {
			observation.FourWaySetComplete = true
		}
	}
	return uint64(len(complete))
}

func findPMKID(data []byte) ([]byte, bool, error) {
	for offset := 0; offset < len(data); {
		if len(data)-offset < 2 {
			return nil, false, fmt.Errorf("truncated EAPOL-Key data element")
		}
		length := int(data[offset+1])
		end := offset + 2 + length
		if end > len(data) {
			return nil, false, fmt.Errorf("EAPOL-Key data element exceeds key-data bounds")
		}
		if data[offset] == 0xdd && length >= 20 {
			value := data[offset+2 : end]
			if value[0] == 0x00 && value[1] == 0x0f && value[2] == 0xac && value[3] == 0x04 {
				return append([]byte(nil), value[4:20]...), true, nil
			}
		}
		offset = end
	}
	return nil, false, nil
}
