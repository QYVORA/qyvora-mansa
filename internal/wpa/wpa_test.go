package wpa

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// RFC 6070 test vectors for PBKDF2-HMAC-SHA1 validate the in-tree implementation
// against the standard before it is trusted with an SSID.
func TestPBKDF2MatchesRFC6070(t *testing.T) {
	cases := []struct {
		password, salt string
		iterations     int
		length         int
		expected       string
	}{
		{"password", "salt", 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6"},
		{"password", "salt", 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"},
		{"password", "salt", 4096, 20, "4b007901b765489abead49d926f721d065a429c1"},
		{"passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"},
		{"pass\x00word", "sa\x00lt", 4096, 16, "56fa6aa75548099dcc37d7f03425e0c3"},
	}
	for _, tc := range cases {
		got, err := pbkdf2Key([]byte(tc.password), []byte(tc.salt), tc.iterations, tc.length, sha1New)
		if err != nil {
			t.Fatalf("pbkdf2(%q): %v", tc.password, err)
		}
		if hex.EncodeToString(got) != tc.expected {
			t.Errorf("pbkdf2(%q, %q, %d) = %s, want %s", tc.password, tc.salt, tc.iterations, hex.EncodeToString(got), tc.expected)
		}
	}
}

func TestDerivePMKIsDeterministicAndSSIDBound(t *testing.T) {
	first, err := DerivePMK("correct horse battery staple", "mansa-lab", KDFSHA1)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != PMKLength {
		t.Fatalf("PMK length = %d, want %d", len(first), PMKLength)
	}
	again, err := DerivePMK("correct horse battery staple", "mansa-lab", KDFSHA1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, again) {
		t.Error("the same passphrase and SSID must derive the same PMK")
	}
	other, err := DerivePMK("correct horse battery staple", "different-ssid", KDFSHA1)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, other) {
		t.Error("the PMK must depend on the SSID")
	}
	sha256PMK, err := DerivePMK("correct horse battery staple", "mansa-lab", KDFSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, sha256PMK) {
		t.Error("the SHA-256 derivation must differ from the SHA-1 derivation")
	}
}

func TestDerivePMKRejectsUnusableInput(t *testing.T) {
	if _, err := DerivePMK("", "ssid", KDFSHA1); err == nil {
		t.Error("an empty passphrase must be rejected")
	}
	if _, err := DerivePMK("pass", "", KDFSHA1); err == nil {
		t.Error("an empty SSID must be rejected")
	}
}

func TestDerivePTKOrdersAddressesAndNonces(t *testing.T) {
	pmk := bytes.Repeat([]byte{0x5a}, PMKLength)
	aNonce := bytes.Repeat([]byte{0x11}, aNonceLength)
	sNonce := bytes.Repeat([]byte{0x22}, sNonceLength)

	// Ordering must not depend on which side is calling.
	forward, err := DerivePTK(pmk, "00:11:22:33:44:55", "66:77:88:99:aa:bb", aNonce, sNonce, KDFSHA1)
	if err != nil {
		t.Fatal(err)
	}
	swapped, err := DerivePTK(pmk, "66:77:88:99:aa:bb", "00:11:22:33:44:55", aNonce, sNonce, KDFSHA1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(forward, swapped) {
		t.Error("PTK derivation must be independent of the caller")
	}
	// Nonce ordering must be symmetric too.
	reversed, err := DerivePTK(pmk, "00:11:22:33:44:55", "66:77:88:99:aa:bb", sNonce, aNonce, KDFSHA1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(forward, reversed) {
		t.Error("PTK derivation must be independent of nonce order")
	}
	if len(forward) != PTKLengthSHA1 {
		t.Fatalf("PTK length = %d, want %d", len(forward), PTKLengthSHA1)
	}
	kck, err := KCK(forward)
	if err != nil {
		t.Fatal(err)
	}
	if len(kck) != 16 {
		t.Fatalf("KCK length = %d, want 16", len(kck))
	}
	if !bytes.Equal(kck, forward[:16]) {
		t.Error("the KCK must be the first 16 bytes of the PTK")
	}
}

func TestDerivePTKRejectsBadInput(t *testing.T) {
	if _, err := DerivePTK(nil, "a", "b", bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), KDFSHA1); err == nil {
		t.Error("an empty PMK must be rejected")
	}
	if _, err := DerivePTK(bytes.Repeat([]byte{1}, 32), "", "b", bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), KDFSHA1); err == nil {
		t.Error("a missing authenticator address must be rejected")
	}
	if _, err := DerivePTK(bytes.Repeat([]byte{1}, 32), "a", "b", []byte{1, 2, 3}, bytes.Repeat([]byte{2}, 32), KDFSHA1); err == nil {
		t.Error("a short ANonce must be rejected")
	}
}

func TestPRFLengthAndCounterDependence(t *testing.T) {
	key := bytes.Repeat([]byte{0xab}, 32)
	seed := []byte("seed material")
	short := prf(key, seed, 16, KDFSHA1)
	if len(short) != 16 {
		t.Fatalf("PRF length = %d, want 16", len(short))
	}
	full := prf(key, seed, 64, KDFSHA1)
	// The first block of a longer request must equal the shorter request.
	if !bytes.Equal(short, full[:16]) {
		t.Error("the PRF must be a prefix-stable stream")
	}
	if bytes.Equal(short, full[16:32]) {
		t.Error("the PRF must vary its output between iterations")
	}
}

func TestDerivePMKFromHex(t *testing.T) {
	key, err := DerivePMKFromHex("00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f")
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != PMKLength {
		t.Fatalf("PMKID length = %d, want %d", len(key), PMKLength)
	}
	if _, err := DerivePMKFromHex("00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f"); err != nil {
		t.Errorf("separated hexadecimal must decode: %v", err)
	}
	for _, bad := range []string{"", "zz", "00000000000000000000000000000000"} {
		if _, err := DerivePMKFromHex(bad); err == nil {
			t.Errorf("expected %q to be rejected", bad)
		}
	}
}

func TestMessageClassification(t *testing.T) {
	cases := []struct {
		info     uint16
		expected string
	}{
		{keyInfoAck, "M1"},
		{keyInfoMIC, "M2"},
		{keyInfoMIC | keyInfoSecure, "M4"},
		{keyInfoAck | keyInfoMIC | keyInfoInstall, "M3"},
		{0, ""},
	}
	for _, tc := range cases {
		if got := Message(tc.info); got != tc.expected {
			t.Errorf("Message(%#04x) = %q, want %q", tc.info, got, tc.expected)
		}
	}
}

func TestMICLengthForMessage(t *testing.T) {
	if got, err := MICLengthForMessage(EAPOLKeyFixedBodySHA1); err != nil || got != MICLengthSHA1 {
		t.Errorf("SHA-1 MIC length = %d, %v", got, err)
	}
	if got, err := MICLengthForMessage(EAPOLKeyFixedBodySHA256); err != nil || got != MICLengthSHA256 {
		t.Errorf("SHA-256 MIC length = %d, %v", got, err)
	}
	if _, err := MICLengthForMessage(80); err == nil {
		t.Error("an unsupported body length must be rejected")
	}
}

func TestVerifyMICDetectsTampering(t *testing.T) {
	kck := bytes.Repeat([]byte{0x77}, 16)
	header := []byte{0x88, 0x8e, 0x00, 0x5f}
	body := make([]byte, EAPOLKeyFixedBodySHA1)
	body[keyInfoOffset] = 0x00
	body[keyInfoOffset+1] = byte(keyInfoMIC >> 8)
	body[keyIVOffset] = 0x01
	body[keyIVOffset+1] = 0x02
	// Fill with deterministic data that must not include the MIC field.
	for i := 0; i < len(body); i++ {
		if i >= micOffset && i < micOffset+MICLengthSHA1 {
			continue
		}
		body[i] = byte(i * 7)
	}
	if VerifyMIC(kck, header, body, micOffset, MICLengthSHA1) {
		t.Fatal("a zero MIC must not verify")
	}
	computed := ComputeMIC(kck, header, body, micOffset, MICLengthSHA1)
	copy(body[micOffset:micOffset+MICLengthSHA1], computed)
	if !VerifyMIC(kck, header, body, micOffset, MICLengthSHA1) {
		t.Error("a correctly computed MIC must verify")
	}
	// A one-bit change in the body must invalidate the MIC.
	tampered := append([]byte(nil), body...)
	tampered[micOffset+MICLengthSHA1] ^= 0xff
	if VerifyMIC(kck, header, tampered, micOffset, MICLengthSHA1) {
		t.Error("a tampered body must not verify")
	}
	// A different KCK must not verify.
	other := bytes.Repeat([]byte{0x78}, 16)
	if VerifyMIC(other, header, body, micOffset, MICLengthSHA1) {
		t.Error("a wrong KCK must not verify")
	}
	// The transmitted MIC must not be part of its own input.
	selfContained := ComputeMIC(kck, header, body, micOffset, MICLengthSHA1)
	if !bytes.Equal(selfContained, computed) {
		t.Error("computing the MIC twice must produce the same value")
	}
}

func TestDescribeBodyDerivesVersionDependentOffsets(t *testing.T) {
	// A SHA-1 message carrying an 8-byte MIC and 8 bytes of key data has a
	// 103-byte body. Padding makes the trailing bytes non-zero so the SHA-256
	// variant cannot also explain it.
	sha1Body := make([]byte, EAPOLKeyFixedBodySHA1+8)
	for i := range sha1Body {
		sha1Body[i] = byte(i + 1)
	}
	sha1Body[micOffset+MICLengthSHA1] = 0x00
	sha1Body[micOffset+MICLengthSHA1+1] = 0x08
	copy(sha1Body[eapolFixedBodyLengthSHA1:], []byte{0xdd, 0x06, 0x00, 0x0f, 0xac, 0x04, 1, 2})
	sha1Layouts, err := DescribeBody(sha1Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(sha1Layouts) != 1 {
		t.Fatalf("SHA-1 body produced %d layouts, want 1", len(sha1Layouts))
	}
	sha1Layout := sha1Layouts[0]
	if sha1Layout.MICLength != MICLengthSHA1 {
		t.Errorf("SHA-1 MIC length = %d, want %d", sha1Layout.MICLength, MICLengthSHA1)
	}
	if sha1Layout.KeyDataOffset != eapolFixedBodyLengthSHA1 {
		t.Errorf("SHA-1 key data offset = %d, want %d", sha1Layout.KeyDataOffset, eapolFixedBodyLengthSHA1)
	}
	if sha1Layout.KeyDataLength != 8 {
		t.Errorf("SHA-1 key data length = %d, want 8", sha1Layout.KeyDataLength)
	}

	// A SHA-256 message has a longer MIC, which moves the key data length field.
	sha256Body := make([]byte, eapolFixedBodyLengthSHA256+4)
	for i := range sha256Body {
		sha256Body[i] = byte(200 - i)
	}
	sha256Body[micOffset+MICLengthSHA256] = 0x00
	sha256Body[micOffset+MICLengthSHA256+1] = 0x04
	copy(sha256Body[eapolFixedBodyLengthSHA256:], []byte{0xdd, 0x06, 0x00, 0x0f, 0xac, 0x04, 9, 9})
	sha256Layouts, err := DescribeBody(sha256Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(sha256Layouts) != 1 {
		t.Fatalf("SHA-256 body produced %d layouts, want 1", len(sha256Layouts))
	}
	sha256Layout := sha256Layouts[0]
	if sha256Layout.MICLength != MICLengthSHA256 {
		t.Errorf("SHA-256 MIC length = %d, want %d", sha256Layout.MICLength, MICLengthSHA256)
	}
	if sha256Layout.KeyDataOffset != eapolFixedBodyLengthSHA256 {
		t.Errorf("SHA-256 key data offset = %d, want %d", sha256Layout.KeyDataOffset, eapolFixedBodyLengthSHA256)
	}
	if sha256Layout.KeyDataLength != 4 {
		t.Errorf("SHA-256 key data length = %d, want 4", sha256Layout.KeyDataLength)
	}
	if !bytes.Equal(KeyData(sha256Body, sha256Layout), []byte{0xdd, 0x06, 0x00, 0x0f}) {
		t.Error("the SHA-256 key data must be read past the longer MIC")
	}
	if len(MIC(sha256Body, sha256Layout)) != MICLengthSHA256 {
		t.Error("the SHA-256 MIC must span 16 bytes")
	}
}

// A body of exactly the fixed length with zero key data cannot be told apart
// between the two suites, so both layouts must be offered rather than one guessed.
func TestDescribeBodyReportsAmbiguousLayouts(t *testing.T) {
	// The SHA-1 variant reads the key data length at offset 93 and the SHA-256
	// variant at offset 101. Setting 93 to 8 and 101 to 0 makes a 103-byte body
	// consistent with SHA-1 plus 8 bytes of key data and with SHA-256 plus none.
	ambiguous := make([]byte, eapolFixedBodyLengthSHA256)
	binary.BigEndian.PutUint16(ambiguous[micOffset+MICLengthSHA1:], 8)
	layouts, err := DescribeBody(ambiguous)
	if err != nil {
		t.Fatal(err)
	}
	if len(layouts) != 2 {
		t.Fatalf("ambiguous body produced %d layouts, want 2", len(layouts))
	}
	seen := map[int]bool{}
	for _, layout := range layouts {
		seen[layout.MICLength] = true
		want := map[int]int{MICLengthSHA1: 8, MICLengthSHA256: 0}
		if layout.KeyDataLength != want[layout.MICLength] {
			t.Errorf("a %d-byte MIC must imply %d bytes of key data, got %d", layout.MICLength, want[layout.MICLength], layout.KeyDataLength)
		}
	}
	if !seen[MICLengthSHA1] || !seen[MICLengthSHA256] {
		t.Errorf("both MIC lengths must be offered, got %v", seen)
	}
}

func TestDescribeBodyRejectsUnsupportedLengths(t *testing.T) {
	for _, length := range []int{0, 94, EAPOLKeyFixedBodySHA1 + 8 + 1, 4096} {
		if _, err := DescribeBody(make([]byte, length)); err == nil {
			t.Errorf("expected a body of %d bytes to be rejected", length)
		}
	}
	// A declared key data length that does not land at the end of the body must
	// be rejected by every layout, so an over-long length cannot be accepted.
	truncated := make([]byte, EAPOLKeyFixedBodySHA1+8)
	for i := range truncated {
		truncated[i] = 1
	}
	truncated[micOffset+MICLengthSHA1] = 0xff
	truncated[micOffset+MICLengthSHA1+1] = 0xfe
	if layouts, err := DescribeBody(truncated); err == nil {
		t.Errorf("expected an over-long key data length to be rejected, got %d layouts", len(layouts))
	}
}

func TestDescribeBodyReadAccessorsRejectShortBodies(t *testing.T) {
	if got := ReplayCounter([]byte{1, 2}); got != 0 {
		t.Errorf("a short body must report no replay counter, got %d", got)
	}
	if ANonce([]byte{1, 2}) != nil || SNonce([]byte{1, 2}) != nil {
		t.Error("a short body must not report a nonce")
	}
	layout := BodyLayout{MICOffset: micOffset, MICLength: MICLengthSHA1, KeyDataOffset: eapolFixedBodyLengthSHA1, KeyDataLength: 4}
	if MIC([]byte{1, 2, 3}, layout) != nil || KeyData([]byte{1, 2, 3}, layout) != nil {
		t.Error("accessors must refuse to read past the body")
	}
}

func TestNonceAccessorsReturnCopies(t *testing.T) {
	body := make([]byte, EAPOLKeyFixedBodySHA1)
	for i := range body {
		body[i] = byte(i)
	}
	first := ANonce(body)
	if !bytes.Equal(first, body[aNonceOffset:aNonceOffset+aNonceLength]) {
		t.Error("the ANonce must be read from the documented offset")
	}
	first[0] ^= 0xff
	if bytes.Equal(ANonce(body), first) {
		t.Error("the accessor must not alias the caller buffer")
	}
	if got := ReplayCounter(body); got != binary.BigEndian.Uint64(body[replayOffset:replayOffset+replayLength]) {
		t.Error("the replay counter must be read as a big-endian uint64")
	}
}
