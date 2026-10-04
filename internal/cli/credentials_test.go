package cli

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QYVORA/qyvora-mansa/internal/exitcode"
	"github.com/QYVORA/qyvora-mansa/internal/wpa"
)

const (
	matchedWording   = "a candidate-derived message integrity code matched the captured code"
	exhaustedWording = "no candidate reproduced a captured message integrity code"
)

const (
	credSSID    = "mansa-lab"
	credBSSID   = "02:00:00:00:00:01"
	credStation = "02:00:00:00:00:02"
	credPass    = "correct horse battery staple"
	credKey1    = 1<<3 | 1<<7
	credKey2    = 1<<3 | 1<<8
)

// writeHandshakePCAP builds a capture whose M2 integrity code really was computed
// from passphrase, so the CLI test exercises the cryptographic path end to end.
func writeHandshakePCAP(t *testing.T, passphrase string, kdf wpa.KDF, micLength int, withBeacon bool) string {
	t.Helper()
	pmk, err := wpa.DerivePMK(passphrase, credSSID, kdf)
	if err != nil {
		t.Fatal(err)
	}
	anonce, snonce := make([]byte, 32), make([]byte, 32)
	for i := range anonce {
		anonce[i] = byte(0xa0 + i)
		snonce[i] = byte(0x50 + i)
	}
	ptk, err := wpa.DerivePTK(pmk, credBSSID, credStation, anonce, snonce, kdf)
	if err != nil {
		t.Fatal(err)
	}
	kck, err := wpa.KCK(ptk)
	if err != nil {
		t.Fatal(err)
	}
	header := func(n int) []byte {
		h := []byte{0x02, 0x03, 0x00, 0x00}
		binary.BigEndian.PutUint16(h[2:], uint16(n))
		return h
	}
	body := func(info uint16) []byte {
		b := make([]byte, wpa.EAPOLKeyBodyLength(micLength, 0))
		b[0] = 2
		binary.BigEndian.PutUint16(b[1:3], info)
		wpa.PutReplayCounter(b, 3)
		copy(b[13:45], snonce)
		if info&(1<<8) != 0 {
			copy(b[45:77], anonce)
			layouts, layoutErr := wpa.DescribeBody(b)
			if layoutErr != nil {
				t.Fatal(layoutErr)
			}
			layout := layouts[0]
			copy(b[layout.MICOffset:layout.MICOffset+micLength], wpa.ComputeMIC(kck, header(len(b)), b, layout.MICOffset, micLength))
		}
		return b
	}

	var out bytes.Buffer
	out.Write([]byte{0xd4, 0xc3, 0xb2, 0xa1})
	binary.LittleEndian.PutUint16(out.Bytes()[4:6], 0) // placeholder, rewritten below
	out.Reset()
	global := make([]byte, 24)
	binary.LittleEndian.PutUint32(global[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(global[4:], 2)
	binary.LittleEndian.PutUint16(global[6:], 4)
	binary.LittleEndian.PutUint32(global[16:], 65535)
	binary.LittleEndian.PutUint32(global[20:], 105)
	out.Write(global)
	write := func(frame []byte) {
		record := make([]byte, 16)
		binary.LittleEndian.PutUint32(record[0:], 1700000000)
		binary.LittleEndian.PutUint32(record[8:], uint32(len(frame)))
		binary.LittleEndian.PutUint32(record[12:], uint32(len(frame)))
		out.Write(record)
		out.Write(frame)
	}
	if withBeacon {
		write(credBeaconFrame())
	}
	write(credEAPOLDataFrame(body(credKey1)))
	write(credEAPOLDataFrame(body(credKey2)))

	path := filepath.Join(t.TempDir(), "handshake.pcap")
	if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func credBeaconFrame() []byte {
	elements := append([]byte{0, byte(len(credSSID))}, credSSID...)
	frame := make([]byte, 24+12+len(elements))
	binary.LittleEndian.PutUint16(frame[0:], 8<<4)
	copy(frame[10:16], []byte{0x02, 0, 0, 0, 0, 1})
	copy(frame[16:22], []byte{0x02, 0, 0, 0, 0, 1})
	copy(frame[24+12:], elements)
	return frame
}

func credEAPOLDataFrame(body []byte) []byte {
	frame := make([]byte, 24+8+4+len(body))
	binary.LittleEndian.PutUint16(frame[0:], 0x0208)
	copy(frame[4:10], []byte{0x02, 0, 0, 0, 0, 2})
	copy(frame[10:16], []byte{0x02, 0, 0, 0, 0, 1})
	copy(frame[16:22], []byte{0x02, 0, 0, 0, 0, 1})
	copy(frame[24:32], []byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e})
	eapol := frame[32:]
	eapol[0] = 2
	eapol[1] = 3
	binary.BigEndian.PutUint16(eapol[2:], uint16(len(body)))
	copy(eapol[4:], body)
	return frame
}

func TestCredentialsVerifyReportsMatchingCandidate(t *testing.T) {
	resetTestApp(t)
	capture := writeHandshakePCAP(t, credPass, wpa.KDFSHA1, wpa.MICLengthSHA1, true)
	args := []string{"credentials", "verify", "--capture", capture, "--ssid", credSSID, "--authorized",
		"--builtin=false", "--candidate", credPass}
	if got := ExecuteArgs(t.Context(), append(args, "-o", "json")); got != exitcode.Success {
		t.Fatalf("exit code = %d, want success", got)
	}
	sess, err := appState.Store.Latest()
	if err != nil {
		t.Fatal(err)
	}
	var matched bool
	for _, evidence := range sess.Evidence {
		if strings.Contains(evidence.Detail, matchedWording) {
			matched = true
		}
	}
	if !matched {
		t.Fatalf("the session must record the verification condition, got %+v", sess.Evidence)
	}
	// The candidate itself must never be written anywhere in the session.
	for _, evidence := range sess.Evidence {
		if bytes.Contains([]byte(evidence.Detail), []byte(credPass)) {
			t.Errorf("evidence leaked the candidate value: %q", evidence.Detail)
		}
	}
}

func TestCredentialsVerifyReportsNoMatch(t *testing.T) {
	resetTestApp(t)
	capture := writeHandshakePCAP(t, credPass, wpa.KDFSHA1, wpa.MICLengthSHA1, true)
	args := []string{"credentials", "verify", "--capture", capture, "--ssid", credSSID, "--authorized",
		"--builtin=false", "--candidate", "definitely not the passphrase", "-o", "json"}
	if got := ExecuteArgs(t.Context(), args); got != exitcode.Success {
		t.Fatalf("exit code = %d, want success for an exhausted search", got)
	}
	sess, err := appState.Store.Latest()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, evidence := range sess.Evidence {
		if strings.Contains(evidence.Detail, exhaustedWording) {
			found = true
		}
	}
	if !found {
		t.Errorf("the session must record the negative result, got %+v", sess.Evidence)
	}
}

func TestCredentialsVerifyVerifiesSHA256Suite(t *testing.T) {
	resetTestApp(t)
	capture := writeHandshakePCAP(t, credPass, wpa.KDFSHA256, wpa.MICLengthSHA256, true)
	args := []string{"credentials", "verify", "--capture", capture, "--ssid", credSSID, "--kdf", "sha256",
		"--authorized", "--builtin=false", "--candidate", credPass, "-o", "json"}
	if got := ExecuteArgs(t.Context(), args); got != exitcode.Success {
		t.Fatalf("exit code = %d", got)
	}
	// The SHA-1 derivation must not satisfy a SHA-256 suite capture.
	resetTestApp(t)
	capture = writeHandshakePCAP(t, credPass, wpa.KDFSHA256, wpa.MICLengthSHA256, true)
	args = []string{"credentials", "verify", "--capture", capture, "--ssid", credSSID, "--kdf", "sha1",
		"--authorized", "--builtin=false", "--candidate", credPass, "-o", "json"}
	if got := ExecuteArgs(t.Context(), args); got != exitcode.Success {
		t.Fatalf("exit code = %d", got)
	}
	sess, err := appState.Store.Latest()
	if err != nil {
		t.Fatal(err)
	}
	for _, evidence := range sess.Evidence {
		if strings.Contains(evidence.Detail, matchedWording) {
			t.Error("the SHA-1 derivation must not satisfy a SHA-256 suite capture")
		}
	}
}

func TestCredentialsVerifyRequiresAuthorization(t *testing.T) {
	resetTestApp(t)
	capture := writeHandshakePCAP(t, credPass, wpa.KDFSHA1, wpa.MICLengthSHA1, true)
	args := []string{"credentials", "verify", "--capture", capture, "--ssid", credSSID, "--builtin=false"}
	if got := ExecuteArgs(t.Context(), args); got != exitcode.AuthorizationRefused {
		t.Fatalf("exit code = %d, want %d without --authorized", got, exitcode.AuthorizationRefused)
	}
}

func TestCredentialsVerifyRequiresExactlyOneTarget(t *testing.T) {
	resetTestApp(t)
	capture := writeHandshakePCAP(t, credPass, wpa.KDFSHA1, wpa.MICLengthSHA1, true)
	for _, target := range [][]string{
		{"credentials", "verify", "--capture", capture, "--authorized"},
		{"credentials", "verify", "--capture", capture, "--ssid", credSSID, "--bssid", credBSSID, "--authorized"},
		{"credentials", "verify", "--ssid", credSSID, "--authorized"},
	} {
		if got := ExecuteArgs(t.Context(), target); got != exitcode.Usage {
			t.Errorf("%v: exit code = %d, want %d", target, got, exitcode.Usage)
		}
	}
}

func TestCredentialsVerifyRefusesCaptureWithoutHandshake(t *testing.T) {
	resetTestApp(t)
	capture := writeHandshakePCAP(t, credPass, wpa.KDFSHA1, wpa.MICLengthSHA1, false)
	args := []string{"credentials", "verify", "--capture", capture, "--ssid", credSSID, "--authorized", "--builtin=false"}
	if got := ExecuteArgs(t.Context(), args); got == exitcode.Success {
		t.Fatal("expected a capture with no handshake to be refused")
	}
}

func TestCredentialsVerifyRefusesTargetAbsentFromCapture(t *testing.T) {
	resetTestApp(t)
	capture := writeHandshakePCAP(t, credPass, wpa.KDFSHA1, wpa.MICLengthSHA1, true)
	args := []string{"credentials", "verify", "--capture", capture, "--ssid", "some-other-network",
		"--authorized", "--builtin=false", "--candidate", credPass}
	if got := ExecuteArgs(t.Context(), args); got == exitcode.Success {
		t.Fatal("expected a target the capture never observed to be refused")
	}
}

func TestCredentialsVerifyRejectsBadFlags(t *testing.T) {
	resetTestApp(t)
	capture := writeHandshakePCAP(t, credPass, wpa.KDFSHA1, wpa.MICLengthSHA1, true)
	for _, args := range [][]string{
		{"credentials", "verify", "--capture", capture, "--ssid", credSSID, "--kdf", "md5", "--authorized"},
		{"credentials", "verify", "--capture", capture, "--ssid", credSSID, "--min-length", "x", "--authorized"},
		{"credentials", "verify", "--capture", capture, "--ssid", credSSID, "--min-length", "8", "--max-length", "4", "--authorized"},
		{"credentials", "verify", "--capture", capture, "--ssid", credSSID, "--max-candidates", "0", "--authorized"},
		{"credentials", "verify", "--capture", filepath.Join(t.TempDir(), "missing.pcap"), "--ssid", credSSID, "--authorized"},
	} {
		if got := ExecuteArgs(t.Context(), args); got != exitcode.Usage {
			t.Errorf("%v: exit code = %d, want %d", args, got, exitcode.Usage)
		}
	}
}

func TestCredentialsVerifyAppliesLengthFilter(t *testing.T) {
	resetTestApp(t)
	capture := writeHandshakePCAP(t, credPass, wpa.KDFSHA1, wpa.MICLengthSHA1, true)
	// A minimum length above the passphrase must filter it out, so no match.
	args := []string{"credentials", "verify", "--capture", capture, "--ssid", credSSID, "--authorized",
		"--builtin=false", "--candidate", credPass, "--min-length", "64"}
	if got := ExecuteArgs(t.Context(), args); got != exitcode.Success {
		t.Fatalf("exit code = %d", got)
	}
	sess, err := appState.Store.Latest()
	if err != nil {
		t.Fatal(err)
	}
	for _, evidence := range sess.Evidence {
		if strings.Contains(evidence.Detail, matchedWording) {
			t.Error("a filtered-out candidate must not verify")
		}
	}
	// The same candidate within the bound must verify.
	resetTestApp(t)
	args = []string{"credentials", "verify", "--capture", capture, "--ssid", credSSID, "--authorized",
		"--builtin=false", "--candidate", credPass, "--min-length", "8", "--max-length", "64"}
	if got := ExecuteArgs(t.Context(), args); got != exitcode.Success {
		t.Fatalf("exit code = %d", got)
	}
	sess, err = appState.Store.Latest()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, evidence := range sess.Evidence {
		if strings.Contains(evidence.Detail, matchedWording) {
			found = true
		}
	}
	if !found {
		t.Error("a candidate within the length bound must verify")
	}
}

func TestCredentialsVerifyChecksBuiltInSet(t *testing.T) {
	resetTestApp(t)
	// The built-in set contains the hyphenated spelling of the passphrase, which
	// is not the captured passphrase, so nothing may match.
	capture := writeHandshakePCAP(t, credPass, wpa.KDFSHA1, wpa.MICLengthSHA1, true)
	args := []string{"credentials", "verify", "--capture", capture, "--ssid", credSSID, "--authorized", "-o", "json"}
	if got := ExecuteArgs(t.Context(), args); got != exitcode.Success {
		t.Fatalf("exit code = %d", got)
	}
	sess, err := appState.Store.Latest()
	if err != nil {
		t.Fatal(err)
	}
	for _, evidence := range sess.Evidence {
		if strings.Contains(evidence.Detail, matchedWording) {
			t.Error("a candidate not in the built-in set must not verify")
		}
	}
	// A built-in entry that is the real passphrase must verify through the default mode.
	resetTestApp(t)
	capture = writeHandshakePCAP(t, "mansa-lab", wpa.KDFSHA1, wpa.MICLengthSHA1, true)
	args = []string{"credentials", "verify", "--capture", capture, "--ssid", credSSID, "--authorized", "-o", "json"}
	if got := ExecuteArgs(t.Context(), args); got != exitcode.Success {
		t.Fatalf("exit code = %d", got)
	}
	sess, err = appState.Store.Latest()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, evidence := range sess.Evidence {
		if strings.Contains(evidence.Detail, matchedWording) {
			found = true
		}
	}
	if !found {
		t.Error("a built-in candidate must verify through the default mode")
	}
}
