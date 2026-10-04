package credentials

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/QYVORA/qyvora-mansa/internal/wpa"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// ErrNoHandshake reports that no capture contained a verifiable WPA or WPA2
// four-way handshake, so no candidate could be checked.
var ErrNoHandshake = errors.New("no verifiable WPA/WPA2 four-way handshake was found in the supplied captures")

// maxHandshakePairs bounds how many distinct handshakes are carried forward so a
// large capture cannot expand memory without limit.
const maxHandshakePairs = 64

// Handshake is the public material required to verify a candidate passphrase
// against a captured four-way handshake. It contains no secret: both nonces are
// transmitted in the clear and the integrity code is a truncated keyed hash.
type Handshake struct {
	SSID    string
	BSSID   string
	Station string
	Message string
	ANonce  []byte
	SNonce  []byte
	MIC     []byte
	MICSize int
	EAPOL   []byte
	// PMKID is a master key observed in a key data element. A capture carrying
	// one can be verified without a passphrase, so the verifier reports that
	// path separately instead of pretending to derive a key.
	PMKID []byte
	// ReplayCounter is the counter carried by the verified message, recorded so
	// evidence can name the exact message that matched.
	ReplayCounter uint64
}

// Describe renders the handshake for evidence output without exposing the
// integrity code as a bare value a reader could mistake for a key.
func (h Handshake) Describe() string {
	kind := "passphrase"
	if len(h.PMKID) > 0 {
		kind = "pmkid"
	}
	return fmt.Sprintf("%s four-way %s for %s (%s/%s), %d-byte MIC, replay counter %d, %s verification",
		h.SSID, h.Message, h.BSSID, h.BSSID, h.Station, h.MICSize, h.ReplayCounter, kind)
}

// HandshakesFromObservations pairs the supplicant nonce carried by an M1 with the
// authenticator nonce and integrity code carried by the following M2, for each
// BSSID and station pair. An observed PMKID is returned on its own because it is
// already a master key and needs no passphrase.
//
// The function never reports a handshake it cannot derive from the capture: an
// integrity code without its matching nonce, or an nonce without an integrity
// code, produces no entry.
func HandshakesFromObservations(observations []models.WirelessAuthenticationObservation) ([]Handshake, error) {
	type pairKey struct{ bssid, station string }
	nonces := make(map[pairKey]map[uint64][]byte)
	byPair := make(map[pairKey]Handshake)
	order := make([]pairKey, 0, len(observations))

	for _, observation := range observations {
		verification := observation.Verification
		if verification == nil || verification.BSSID == "" || observation.Station == "" {
			continue
		}
		// A PMKID is itself a master key and is verified on its own.
		if pmkid, err := hex.DecodeString(verification.PMKID); err == nil && len(pmkid) > 0 {
			key := pairKey{observation.BSSID, observation.Station}
			if _, seen := byPair[key]; !seen && len(byPair) < maxHandshakePairs {
				order = append(order, key)
				byPair[key] = Handshake{
					SSID: verification.SSID, BSSID: observation.BSSID, Station: observation.Station,
					Message: observation.Message, PMKID: pmkid, ReplayCounter: observation.ReplayCounter,
				}
			}
			continue
		}
		key := pairKey{observation.BSSID, observation.Station}
		counter := observation.ReplayCounter

		// An M1 carries no integrity code, only the supplicant nonce a later
		// message needs, so it is recorded before the integrity code is required.
		if observation.Message == "M1" {
			if !verification.SNonceValid {
				continue
			}
			set := nonces[key]
			if set == nil {
				if len(nonces) >= maxHandshakePairs {
					continue
				}
				set = make(map[uint64][]byte)
				nonces[key] = set
			}
			if snonce, err := hex.DecodeString(verification.SNonce); err == nil && len(snonce) == 32 {
				set[counter] = snonce
			}
			continue
		}

		// Any other message must carry an integrity code and the authenticator
		// nonce, plus the supplicant nonce from the M1 at the same counter.
		if len(verification.Candidates) == 0 || verification.ANonce == "" {
			continue
		}
		{
			set := nonces[key]
			if set == nil {
				continue
			}
			snonce, ok := set[counter]
			if !ok {
				continue
			}
			anonce, err := hex.DecodeString(verification.ANonce)
			if err != nil || len(anonce) != 32 {
				continue
			}
			eapol, err := hex.DecodeString(verification.CapturedEAPOL)
			if err != nil {
				continue
			}
			mic, err := hex.DecodeString(verification.Candidates[0].MIC)
			if err != nil || len(mic) != verification.Candidates[0].MICLength {
				continue
			}
			if _, seen := byPair[key]; seen {
				continue
			}
			if len(byPair) >= maxHandshakePairs {
				break
			}
			order = append(order, key)
			byPair[key] = Handshake{
				SSID: verification.SSID, BSSID: observation.BSSID, Station: observation.Station,
				Message: observation.Message, ANonce: anonce, SNonce: snonce, MIC: mic,
				MICSize: verification.Candidates[0].MICLength, EAPOL: eapol, ReplayCounter: counter,
			}
		}
	}
	if len(byPair) == 0 {
		return nil, ErrNoHandshake
	}
	handshakes := make([]Handshake, 0, len(order))
	for _, key := range order {
		handshakes = append(handshakes, byPair[key])
	}
	return handshakes, nil
}

// WPAVerifier checks candidates against captured four-way handshakes. It reports
// a match only when the integrity code recomputed from the candidate-derived
// temporal key equals the code the peer transmitted.
type WPAVerifier struct {
	Handshakes []Handshake
	// KDF selects the passphrase derivation. It defaults to the SHA-1 suites.
	KDF wpa.KDF
}

// NewWPAVerifier returns a verifier for the given handshakes, or
// ErrNoHandshake when none were derived.
func NewWPAVerifier(handshakes []Handshake) (*WPAVerifier, error) {
	if len(handshakes) == 0 {
		return nil, ErrNoHandshake
	}
	return &WPAVerifier{Handshakes: handshakes}, nil
}

// Supports reports whether the verifier can check the given target type.
func (v *WPAVerifier) Supports(targetType models.TargetType) bool {
	return targetType == models.TargetSSID || targetType == models.TargetBSSID
}

// Verify checks one candidate against every captured handshake. It returns the
// first handshake whose integrity code matches, and reports no match without an
// error when the candidate is simply wrong.
func (v *WPAVerifier) Verify(ctx context.Context, target *models.Target, candidate string) (Verification, error) {
	if err := ctx.Err(); err != nil {
		return Verification{}, err
	}
	if len(v.Handshakes) == 0 {
		return Verification{}, ErrNoHandshake
	}
	if candidate == "" {
		return Verification{}, errors.New("an empty candidate cannot verify")
	}
	// The target must match the capture, otherwise a candidate could be reported
	// as the key to a network the capture never observed.
	if err := checkTargetScope(target, v.Handshakes); err != nil {
		return Verification{}, err
	}

	for _, handshake := range v.Handshakes {
		if err := ctx.Err(); err != nil {
			return Verification{}, err
		}
		pmk, err := v.masterKey(handshake, candidate)
		if err != nil || pmk == nil {
			continue
		}
		verified, evidence, err := verifyAgainst(handshake, pmk, v.kdf())
		if err != nil {
			continue
		}
		if verified {
			return Verification{Matched: true, Evidence: evidence}, nil
		}
	}
	return Verification{}, nil
}

func (v *WPAVerifier) kdf() wpa.KDF {
	if v.KDF == wpa.KDFSHA256 {
		return wpa.KDFSHA256
	}
	return wpa.KDFSHA1
}

// masterKey returns the pairwise master key implied by a candidate, or nil when
// the handshake cannot be keyed from a passphrase at all.
func (v *WPAVerifier) masterKey(handshake Handshake, candidate string) ([]byte, error) {
	if len(handshake.PMKID) > 0 {
		// A captured PMKID is the master key. A passphrase cannot be checked
		// against it, so the caller is told rather than fed a false derivation.
		return nil, fmt.Errorf("the capture contains a PMKID, so %q cannot be checked against it", candidate)
	}
	return wpa.DerivePMK(candidate, handshake.SSID, v.kdf())
}

// checkTargetScope refuses a target the supplied handshakes never observed. An
// empty target value means no scope was requested, which the caller has already
// authorized separately.
func checkTargetScope(target *models.Target, handshakes []Handshake) error {
	if target == nil || target.Value == "" {
		return nil
	}
	switch target.Type {
	case models.TargetSSID:
		for _, handshake := range handshakes {
			if handshake.SSID == target.Value {
				return nil
			}
		}
		return fmt.Errorf("no captured handshake belongs to SSID %q", target.Value)
	case models.TargetBSSID:
		for _, handshake := range handshakes {
			if strings.EqualFold(handshake.BSSID, target.Value) {
				return nil
			}
		}
		return fmt.Errorf("no captured handshake belongs to BSSID %q", target.Value)
	default:
		return nil
	}
}

// verifyAgainst recomputes the integrity code of one captured message from a
// master key and compares it with the transmitted code.
func verifyAgainst(handshake Handshake, pmk []byte, kdf wpa.KDF) (bool, []string, error) {
	if handshake.SSID == "" {
		return false, nil, errors.New("the capture contains no SSID, so no pairwise master key can be derived")
	}
	ptk, err := wpa.DerivePTK(pmk, handshake.BSSID, handshake.Station, handshake.ANonce, handshake.SNonce, kdf)
	if err != nil {
		return false, nil, err
	}
	kck, err := wpa.KCK(ptk)
	if err != nil {
		return false, nil, err
	}
	if len(handshake.EAPOL) < 4 {
		return false, nil, errors.New("the captured EAPOL message is too short")
	}
	header := handshake.EAPOL[:4]
	body := handshake.EAPOL[4:]
	layouts, err := wpa.DescribeBody(body)
	if err != nil {
		return false, nil, err
	}
	for _, layout := range layouts {
		if layout.MICLength != handshake.MICSize {
			continue
		}
		if wpa.VerifyMIC(kck, header, body, layout.MICOffset, layout.MICLength) {
			evidence := []string{
				handshake.Describe(),
				"the message integrity code recomputed from the candidate matched the transmitted code",
				"only a passphrased key check was performed; the temporal key was derived in memory and not written to disk",
			}
			return true, evidence, nil
		}
	}
	return false, nil, nil
}

// ErrNoSSID reports that no captured handshake could be tied to a network name.
// The SSID is an input to the passphrase derivation, so a candidate cannot be
// checked at all and reporting a non-match would be misleading.
var ErrNoSSID = errors.New("no captured handshake could be tied to a network name, so no passphrase can be derived")

// PassphraseHandshakes returns the handshakes a passphrase can be checked
// against. A handshake captured without a beacon or probe response naming the
// network has no SSID and is excluded, so it is never silently reported as a
// candidate miss.
func PassphraseHandshakes(handshakes []Handshake) ([]Handshake, error) {
	usable := make([]Handshake, 0, len(handshakes))
	for _, handshake := range handshakes {
		// A PMKID is already a master key, so it needs no SSID.
		if handshake.SSID != "" || len(handshake.PMKID) > 0 {
			usable = append(usable, handshake)
		}
	}
	if len(usable) == 0 {
		return nil, ErrNoSSID
	}
	return usable, nil
}
