package credentials

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/QYVORA/qyvora-mansa/internal/wpa"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

const (
	testSSID      = "mansa-lab"
	testBSSID     = "02:00:00:00:00:01"
	testStation   = "02:00:00:00:00:02"
	testPass      = "correct horse battery staple"
	testM2KeyInfo = 1<<3 | 1<<8
	testM1KeyInfo = 1<<3 | 1<<7
)

// buildFourWay constructs an M1 and M2 pair the way an authenticator and a
// supplicant would, so a verification test exercises the real derivation path
// instead of comparing the implementation with itself.
func buildFourWay(t *testing.T, passphrase string, kdf wpa.KDF, micLength int) []models.WirelessAuthenticationObservation {
	t.Helper()
	pmk, err := wpa.DerivePMK(passphrase, testSSID, kdf)
	if err != nil {
		t.Fatal(err)
	}
	anonce := make([]byte, 32)
	snonce := make([]byte, 32)
	for i := range anonce {
		anonce[i] = byte(0xa0 + i)
		snonce[i] = byte(0x50 + i)
	}
	ptk, err := wpa.DerivePTK(pmk, testBSSID, testStation, anonce, snonce, kdf)
	if err != nil {
		t.Fatal(err)
	}
	kck, err := wpa.KCK(ptk)
	if err != nil {
		t.Fatal(err)
	}
	const counter = uint64(7)
	m1 := eapolKeyBody(micLength)
	binaryInfo(m1, testM1KeyInfo)
	wpa.PutReplayCounter(m1, counter)
	copy(m1[13:45], snonce)

	m2 := eapolKeyBody(micLength)
	binaryInfo(m2, testM2KeyInfo)
	wpa.PutReplayCounter(m2, counter)
	copy(m2[45:77], anonce)
	layouts, err := wpa.DescribeBody(m2)
	if err != nil {
		t.Fatal(err)
	}
	layout := layouts[0]
	copy(m2[layout.MICOffset:layout.MICOffset+micLength], wpa.ComputeMIC(kck, eapolHeader(len(m2)), m2, layout.MICOffset, micLength))
	m1EAPOL := append(append([]byte(nil), eapolHeader(len(m1))...), m1...)
	m2EAPOL := append(append([]byte(nil), eapolHeader(len(m2))...), m2...)

	bssidText := testBSSID
	stationText := testStation
	return []models.WirelessAuthenticationObservation{
		{
			BSSID: bssidText, Station: stationText, Kind: "handshake-message", Message: "M1",
			ReplayCounter: counter, ObservedAt: nowForTest(),
			Verification: &models.EAPOLKeyVerification{
				Message: "M1", KeyInfo: testM1KeyInfo, BSSID: bssidText, SSID: testSSID,
				ANonce: hex.EncodeToString(anonce), SNonce: hex.EncodeToString(snonce), SNonceValid: true,
				ReplayCounter: counter,
				CapturedEAPOL: hex.EncodeToString(m1EAPOL),
			},
		},
		{
			BSSID: bssidText, Station: stationText, Kind: "handshake-message", Message: "M2",
			ReplayCounter: counter, ObservedAt: nowForTest(),
			Verification: &models.EAPOLKeyVerification{
				Message: "M2", KeyInfo: testM2KeyInfo, BSSID: bssidText, SSID: testSSID,
				ANonce:        hex.EncodeToString(anonce),
				ReplayCounter: counter,
				Candidates:    []models.EAPOLKeyCandidate{{MICLength: micLength, MIC: hex.EncodeToString(m2[layout.MICOffset : layout.MICOffset+micLength])}},
				CapturedEAPOL: hex.EncodeToString(m2EAPOL),
			},
		},
	}
}

// eapolKeyBody builds a fixed EAPOL-Key body with no key data, so its length is
// the fixed fields through the key data length field.
func eapolKeyBody(micLength int) []byte {
	return make([]byte, wpa.EAPOLKeyBodyLength(micLength, 0))
}

// eapolHeader builds the four-byte EAPOL header a peer transmits ahead of the key
// body: version 2, EAPOL-Key, then the body length.
func eapolHeader(bodyLength int) []byte {
	header := []byte{0x02, 0x03, 0x00, 0x00}
	binary.BigEndian.PutUint16(header[2:], uint16(bodyLength))
	return header
}

func binaryInfo(body []byte, info uint16) {
	body[0] = 2
	binary.BigEndian.PutUint16(body[1:3], info)
}

func nowForTest() time.Time { return time.Unix(1700000000, 0).UTC() }

func TestHandshakesFromObservationsPairsNonces(t *testing.T) {
	handshakes, err := HandshakesFromObservations(buildFourWay(t, testPass, wpa.KDFSHA1, wpa.MICLengthSHA1))
	if err != nil {
		t.Fatal(err)
	}
	if len(handshakes) != 1 {
		t.Fatalf("got %d handshakes, want 1", len(handshakes))
	}
	handshake := handshakes[0]
	if handshake.SSID != testSSID || handshake.BSSID != testBSSID || handshake.Station != testStation {
		t.Errorf("handshake identity = %s/%s/%s", handshake.SSID, handshake.BSSID, handshake.Station)
	}
	if len(handshake.ANonce) != 32 || len(handshake.SNonce) != 32 {
		t.Errorf("nonces = %d and %d bytes, want 32 each", len(handshake.ANonce), len(handshake.SNonce))
	}
	if len(handshake.MIC) != wpa.MICLengthSHA1 {
		t.Errorf("MIC = %d bytes, want %d", len(handshake.MIC), wpa.MICLengthSHA1)
	}
	if len(handshake.EAPOL) != 4+wpa.EAPOLKeyBodyLength(wpa.MICLengthSHA1, 0) {
		t.Errorf("captured EAPOL = %d bytes", len(handshake.EAPOL))
	}
	if describe := handshake.Describe(); !strings.Contains(describe, testSSID) || !strings.Contains(describe, "passphrase verification") {
		t.Errorf("Describe = %q", describe)
	}
}

func TestHandshakesFromObservationsRequiresMatchingCounter(t *testing.T) {
	observations := buildFourWay(t, testPass, wpa.KDFSHA1, wpa.MICLengthSHA1)
	// Move the M1 to a different replay counter than the M2. The nonce pair is
	// then not from the same exchange, so nothing may be verified.
	observations[0].Verification.ReplayCounter = 6
	observations[0].ReplayCounter = 6
	if _, err := HandshakesFromObservations(observations); err == nil {
		t.Error("expected a nonce at a different replay counter to be rejected")
	}
}

func TestHandshakesFromObservationsRejectsM2WithoutM1(t *testing.T) {
	observations := buildFourWay(t, testPass, wpa.KDFSHA1, wpa.MICLengthSHA1)
	withoutM1 := []models.WirelessAuthenticationObservation{observations[1]}
	if _, err := HandshakesFromObservations(withoutM1); err == nil {
		t.Error("expected an M2 without its M1 supplicant nonce to be rejected")
	}
}

func TestHandshakesFromObservationsReportsAbsence(t *testing.T) {
	for _, observations := range [][]models.WirelessAuthenticationObservation{
		nil,
		{{BSSID: testBSSID, Station: testStation, Message: "M1", Verification: nil}},
		{{BSSID: testBSSID, Station: testStation, Message: "M2", Verification: &models.EAPOLKeyVerification{BSSID: testBSSID, Candidates: []models.EAPOLKeyCandidate{{MICLength: 8, MIC: "00"}}}}},
	} {
		if _, err := HandshakesFromObservations(observations); err == nil {
			t.Errorf("expected %v to report no handshake", observations)
		}
	}
}

func TestWPAVerifierAcceptsCorrectPassphrase(t *testing.T) {
	verifier, err := NewWPAVerifier(mustHandshakes(t, buildFourWay(t, testPass, wpa.KDFSHA1, wpa.MICLengthSHA1)))
	if err != nil {
		t.Fatal(err)
	}
	result, err := verifier.Verify(context.Background(), nil, testPass)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Matched {
		t.Fatal("the correct passphrase must verify")
	}
	if len(result.Evidence) == 0 {
		t.Fatal("a match must carry evidence")
	}
	if !strings.Contains(strings.Join(result.Evidence, " "), "matched the transmitted code") {
		t.Errorf("evidence must state what was checked, got %v", result.Evidence)
	}
}

func TestWPAVerifierRejectsWrongPassphraseWithoutError(t *testing.T) {
	verifier, err := NewWPAVerifier(mustHandshakes(t, buildFourWay(t, testPass, wpa.KDFSHA1, wpa.MICLengthSHA1)))
	if err != nil {
		t.Fatal(err)
	}
	result, err := verifier.Verify(context.Background(), nil, "wrong passphrase")
	if err != nil {
		t.Fatalf("a wrong passphrase must not be an error: %v", err)
	}
	if result.Matched {
		t.Fatal("a wrong passphrase must not verify")
	}
}

func TestWPAVerifierVerifiesSHA256Suite(t *testing.T) {
	handshakes := mustHandshakes(t, buildFourWay(t, testPass, wpa.KDFSHA256, wpa.MICLengthSHA256))
	verifier, err := NewWPAVerifier(handshakes)
	if err != nil {
		t.Fatal(err)
	}
	verifier.KDF = wpa.KDFSHA256
	if result, err := verifier.Verify(context.Background(), nil, testPass); err != nil || !result.Matched {
		t.Fatalf("the SHA-256 suite must verify its own passphrase: matched=%v err=%v", result.Matched, err)
	}
	// The SHA-1 derivation must not satisfy a SHA-256 suite handshake.
	sha1Verifier, err := NewWPAVerifier(handshakes)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := sha1Verifier.Verify(context.Background(), nil, testPass); err != nil || result.Matched {
		t.Fatalf("a SHA-1 derivation must not satisfy a SHA-256 suite: matched=%v err=%v", result.Matched, err)
	}
}

func TestWPAVerifierRejectsTargetMismatch(t *testing.T) {
	verifier, err := NewWPAVerifier(mustHandshakes(t, buildFourWay(t, testPass, wpa.KDFSHA1, wpa.MICLengthSHA1)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(context.Background(), &models.Target{Type: models.TargetSSID, Value: "other-network"}, testPass); err == nil {
		t.Error("expected an SSID mismatch to be refused")
	}
	if _, err := verifier.Verify(context.Background(), &models.Target{Type: models.TargetBSSID, Value: "02:00:00:00:00:09"}, testPass); err == nil {
		t.Error("expected a BSSID mismatch to be refused")
	}
	if result, err := verifier.Verify(context.Background(), &models.Target{Type: models.TargetSSID, Value: testSSID}, testPass); err != nil || !result.Matched {
		t.Errorf("a matching target must verify: matched=%v err=%v", result.Matched, err)
	}
}

func TestWPAVerifierRefusesEmptyCandidateAndContext(t *testing.T) {
	verifier, err := NewWPAVerifier(mustHandshakes(t, buildFourWay(t, testPass, wpa.KDFSHA1, wpa.MICLengthSHA1)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(context.Background(), nil, ""); err == nil {
		t.Error("expected an empty candidate to be refused")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := verifier.Verify(cancelled, nil, testPass); err == nil {
		t.Error("expected a cancelled context to stop verification")
	}
	if _, err := NewWPAVerifier(nil); err == nil {
		t.Error("expected an empty handshake set to be refused")
	}
}

func TestWPAVerifierRefusesPassphraseAgainstPMKID(t *testing.T) {
	// A captured PMKID is itself a master key, so a passphrase cannot be checked
	// against it. Reporting a match or a miss would both be wrong.
	observations := []models.WirelessAuthenticationObservation{{
		BSSID: testBSSID, Station: testStation, Message: "M2", ReplayCounter: 7,
		Verification: &models.EAPOLKeyVerification{
			BSSID: testBSSID, SSID: testSSID, PMKID: hex.EncodeToString(make([]byte, 32)),
			ANonce:     hex.EncodeToString(make([]byte, 32)),
			Candidates: []models.EAPOLKeyCandidate{{MICLength: wpa.MICLengthSHA1, MIC: "0000000000000000"}},
		},
	}}
	handshakes, err := HandshakesFromObservations(observations)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewWPAVerifier(handshakes)
	if err != nil {
		t.Fatal(err)
	}
	result, err := verifier.Verify(context.Background(), nil, testPass)
	if err != nil {
		t.Fatalf("a PMKID capture must not error on a passphrase: %v", err)
	}
	if result.Matched {
		t.Error("a passphrase must never be reported as matching a PMKID capture")
	}
	if describe := handshakes[0].Describe(); !strings.Contains(describe, "pmkid verification") {
		t.Errorf("Describe = %q", describe)
	}
}

func TestWPAVerifierRefusesHandshakeWithoutSSID(t *testing.T) {
	observations := buildFourWay(t, testPass, wpa.KDFSHA1, wpa.MICLengthSHA1)
	for i := range observations {
		observations[i].Verification.SSID = ""
	}
	verifier, err := NewWPAVerifier(mustHandshakes(t, observations))
	if err != nil {
		t.Fatal(err)
	}
	result, err := verifier.Verify(context.Background(), nil, testPass)
	if err != nil {
		t.Fatalf("a handshake with no SSID must not error: %v", err)
	}
	if result.Matched {
		t.Error("a handshake with no SSID must not verify")
	}
}

func TestWPAVerifierSupportsOnlyWirelessTargets(t *testing.T) {
	verifier, err := NewWPAVerifier(mustHandshakes(t, buildFourWay(t, testPass, wpa.KDFSHA1, wpa.MICLengthSHA1)))
	if err != nil {
		t.Fatal(err)
	}
	if !verifier.Supports(models.TargetSSID) || !verifier.Supports(models.TargetBSSID) {
		t.Error("the verifier must support wireless target types")
	}
	if verifier.Supports(models.TargetBluetoothAdapter) || verifier.Supports(models.TargetInterface) {
		t.Error("the verifier must refuse unrelated target types")
	}
}

func mustHandshakes(t *testing.T, observations []models.WirelessAuthenticationObservation) []Handshake {
	t.Helper()
	handshakes, err := HandshakesFromObservations(observations)
	if err != nil {
		t.Fatal(err)
	}
	return handshakes
}

func TestPassphraseHandshakesExcludesCapturesWithNoNetworkName(t *testing.T) {
	observations := buildFourWay(t, testPass, wpa.KDFSHA1, wpa.MICLengthSHA1)
	for i := range observations {
		observations[i].Verification.SSID = ""
	}
	handshakes := mustHandshakes(t, observations)
	if _, err := PassphraseHandshakes(handshakes); err == nil {
		t.Fatal("a handshake with no SSID must be refused rather than reported as a miss")
	}
	// A PMKID needs no SSID, so it stays usable.
	pmkidHandshakes := []Handshake{{SSID: "", BSSID: testBSSID, PMKID: make([]byte, 32)}}
	usable, err := PassphraseHandshakes(pmkidHandshakes)
	if err != nil {
		t.Fatalf("a PMKID handshake must stay usable: %v", err)
	}
	if len(usable) != 1 {
		t.Fatalf("got %d usable handshakes, want 1", len(usable))
	}
	if _, err := PassphraseHandshakes(nil); err == nil {
		t.Fatal("expected an empty set to report no usable handshake")
	}
}

func TestPassphraseHandshakesKeepsNamedHandshakes(t *testing.T) {
	usable, err := PassphraseHandshakes(mustHandshakes(t, buildFourWay(t, testPass, wpa.KDFSHA1, wpa.MICLengthSHA1)))
	if err != nil {
		t.Fatal(err)
	}
	if len(usable) != 1 || usable[0].SSID != testSSID {
		t.Fatalf("a named handshake must remain usable, got %+v", usable)
	}
}
