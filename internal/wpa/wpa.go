// Package wpa implements the WPA/WPA2-PBKDF2 key derivations and the
// four-way handshake checks needed to verify a candidate passphrase against a
// captured EAPOL-Key message.
//
// The derivations follow IEEE 802.11-2004 through IEEE 802.11-2020. Nothing
// here guesses: a candidate is accepted only when the message integrity code
// recomputed over the captured message equals the one the peer transmitted.
package wpa

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

// PMK lengths produced by each supported passphrase KDF.
const (
	// Both the SHA-1 and SHA-256 PSK derivations produce a 32-byte PMK.
	PMKLength = 32
	// PMKLengthSHA384 accepts a SHA-384 suite PMKID.
	PMKLengthSHA384 = 48
)

// PTK lengths. The KCK is the first 16 bytes, the KEK the next 16, and the TK
// the remainder.
const (
	PTKLengthSHA1   = 64
	PTKLengthSHA256 = 64
)

// Key derivation function variants for PSK ciphersuites.
type KDF int

const (
	// KDFSHA1 covers WPA-PTK and WPA2-PTK (Suite-B and PSK legacy suites).
	KDFSHA1 KDF = iota
	// KDFSHA256 covers the RSN AKM 00-0F and 8-64 SHA-256 suites.
	KDFSHA256
)

func (k KDF) String() string {
	if k == KDFSHA256 {
		return "sha256"
	}
	return "sha1"
}

// MIC sizes. WPA and WPA2-PTK truncate HMAC-SHA1 to 80 bits, while the
// SHA-256 suites truncate HMAC-SHA1 to 128 bits.
const (
	MICLengthSHA1   = 8
	MICLengthSHA256 = 16
)

// PBKDF2Iterations is the iteration count mandated for the PSK KDF.
const PBKDF2Iterations = 4096

// MIC sizes implied by the observed EAPOL-Key message length.
const (
	// EAPOLKeyFixedBodySHA1 is the descriptor through the key data length for a
	// message carrying an 8-byte key MIC: 1 + 2 + 2 + 8 + 32 + 32 + 8 + 8 + 2.
	EAPOLKeyFixedBodySHA1 = 95
	// EAPOLKeyFixedBodySHA256 adds the 8 extra MIC bytes.
	EAPOLKeyFixedBodySHA256 = 103

	// eapolFixedBodyLengthSHA1 and eapolFixedBodyLengthSHA256 name the same two
	// lengths in the terminology used by the parser and its tests.
	eapolFixedBodyLengthSHA1   = EAPOLKeyFixedBodySHA1
	eapolFixedBodyLengthSHA256 = EAPOLKeyFixedBodySHA256

	// minEAPOLKeyBody is the smallest fixed body, which is the SHA-1 variant.
	minEAPOLKeyBody = EAPOLKeyFixedBodySHA1
)

// EAPOL-Key body field offsets, relative to the descriptor type byte. Every
// offset is fixed except the message integrity code, whose length is implied by
// the body size and which therefore shifts the key data that follows it.
const (
	keyInfoOffset = 1
	replayOffset  = 5
	sNonceOffset  = 13
	aNonceOffset  = 45
	keyIVOffset   = 77
	micOffset     = 85
	keyIVLength   = 8
	sNonceLength  = 32
	aNonceLength  = 32
	replayLength  = 8
)

// BodyLayout locates the version-dependent fields of an EAPOL-Key body.
type BodyLayout struct {
	// MICLength is 8 for the SHA-1 suites and 16 for the SHA-256 suites. The
	// length is inferred from the body, so it is a candidate rather than a fact.
	MICLength int
	// MICOffset is where the key integrity code starts.
	MICOffset int
	// KeyDataLengthOffset is where the two-byte key data length is stored.
	KeyDataLengthOffset int
	// KeyDataOffset is where the key data begins.
	KeyDataOffset int
	// KeyDataLength is the declared key data length.
	KeyDataLength int
	// BodyLength is the observed fixed body length the layout was derived from.
	BodyLength int
}

// DescribeBody derives every field layout consistent with an observed EAPOL-Key
// body.
//
// The key integrity code length is fixed by the negotiated cipher suite, which
// is not carried in the frame, so a body whose key data length cannot be told
// apart between the SHA-1 and SHA-256 variants legitimately matches both. Every
// consistent layout is therefore returned and a caller that verifies a candidate
// key must try each one. A body no variant explains is rejected rather than
// guessed, so an unsupported suite never yields a false verification.
func DescribeBody(body []byte) ([]BodyLayout, error) {
	if len(body) < minEAPOLKeyBody {
		return nil, fmt.Errorf("EAPOL-Key body of %d bytes is shorter than the %d-byte minimum", len(body), minEAPOLKeyBody)
	}
	var layouts []BodyLayout
	for _, micLength := range []int{MICLengthSHA1, MICLengthSHA256} {
		if layout, ok := layoutForMICLength(body, micLength); ok {
			layouts = append(layouts, layout)
		}
	}
	if len(layouts) == 0 {
		return nil, fmt.Errorf("EAPOL-Key body of %d bytes matches no supported MIC layout", len(body))
	}
	return layouts, nil
}

// layoutForMICLength builds the layout implied by a MIC size and reports whether
// the declared key data length lands exactly at the end of the body.
func layoutForMICLength(body []byte, micLength int) (BodyLayout, bool) {
	layout := BodyLayout{
		MICLength:           micLength,
		MICOffset:           micOffset,
		KeyDataLengthOffset: micOffset + micLength,
		KeyDataOffset:       micOffset + micLength + 2,
		BodyLength:          len(body),
	}
	if layout.KeyDataLengthOffset+2 > len(body) {
		return BodyLayout{}, false
	}
	layout.KeyDataLength = int(binary.BigEndian.Uint16(body[layout.KeyDataLengthOffset : layout.KeyDataLengthOffset+2]))
	if layout.KeyDataOffset+layout.KeyDataLength != len(body) {
		return BodyLayout{}, false
	}
	return layout, true
}

// ReplayCounter returns the replay counter carried by an EAPOL-Key body.
func ReplayCounter(body []byte) uint64 {
	if len(body) < replayOffset+replayLength {
		return 0
	}
	return binary.BigEndian.Uint64(body[replayOffset : replayOffset+replayLength])
}

// ANonce returns the authenticator nonce of an EAPOL-Key body.
func ANonce(body []byte) []byte {
	if len(body) < aNonceOffset+aNonceLength {
		return nil
	}
	return append([]byte(nil), body[aNonceOffset:aNonceOffset+aNonceLength]...)
}

// SNonce returns the supplicant nonce of an EAPOL-Key body, which only an M1
// carries in a four-way handshake.
func SNonce(body []byte) []byte {
	if len(body) < sNonceOffset+sNonceLength {
		return nil
	}
	return append([]byte(nil), body[sNonceOffset:sNonceOffset+sNonceLength]...)
}

// MIC returns the transmitted key integrity code described by a layout.
func MIC(body []byte, layout BodyLayout) []byte {
	if layout.MICOffset+layout.MICLength > len(body) {
		return nil
	}
	return body[layout.MICOffset : layout.MICOffset+layout.MICLength]
}

// KeyData returns the key data described by a layout.
func KeyData(body []byte, layout BodyLayout) []byte {
	if layout.KeyDataOffset+layout.KeyDataLength > len(body) {
		return nil
	}
	return body[layout.KeyDataOffset : layout.KeyDataOffset+layout.KeyDataLength]
}

// Key Info bits used to classify a handshake message.
const (
	keyInfoAck     = 1 << 7
	keyInfoMIC     = 1 << 8
	keyInfoSecure  = 1 << 9
	keyInfoInstall = 1 << 6
)

// MICLengthForMessage returns the key MIC size implied by a fixed EAPOL-Key body
// length, or an error when the length is not a supported variant.
func MICLengthForMessage(fixedBodyLength int) (int, error) {
	switch fixedBodyLength {
	case EAPOLKeyFixedBodySHA1:
		return MICLengthSHA1, nil
	case EAPOLKeyFixedBodySHA256:
		return MICLengthSHA256, nil
	default:
		return 0, fmt.Errorf("unsupported EAPOL-Key fixed body length %d", fixedBodyLength)
	}
}

// Message classifies an EAPOL-Key exchange message.
func Message(keyInfo uint16) string {
	switch {
	case keyInfo&keyInfoAck != 0 && keyInfo&keyInfoMIC == 0:
		return "M1"
	case keyInfo&keyInfoAck == 0 && keyInfo&keyInfoMIC != 0 && keyInfo&keyInfoSecure == 0:
		return "M2"
	case keyInfo&keyInfoAck != 0 && keyInfo&keyInfoMIC != 0 && keyInfo&keyInfoInstall != 0:
		return "M3"
	case keyInfo&keyInfoAck == 0 && keyInfo&keyInfoMIC != 0 && keyInfo&keyInfoSecure != 0:
		return "M4"
	default:
		return ""
	}
}

// DerivePMK computes the pairwise master key from a passphrase. The SHA-1
// variant derives 32 bytes after the mandated 4096 iterations; the SHA-256
// variant is defined by IEEE 802.11-2020 and uses SHA-256 instead.
func DerivePMK(passphrase, ssid string, kdf KDF) ([]byte, error) {
	if passphrase == "" {
		return nil, errors.New("an empty passphrase cannot produce a pairwise master key")
	}
	if ssid == "" {
		return nil, errors.New("an empty SSID cannot produce a pairwise master key")
	}
	return pbkdf2Key([]byte(passphrase), []byte(ssid), PBKDF2Iterations, PMKLength, kdf.hashFunc())
}

// DerivePMKFromHex builds the pairwise master key directly from a PMKID observed
// in a KDE. A PMKID is the master key itself, so no derivation is needed.
func DerivePMKFromHex(hexKey string) ([]byte, error) {
	key, err := decodeHex(hexKey)
	if err != nil {
		return nil, fmt.Errorf("decode PMKID: %w", err)
	}
	switch len(key) {
	case PMKLength, PMKLengthSHA384:
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported PMKID length %d", len(key))
	}
}

// DerivePTK computes the pairwise temporal key from the master key, the two
// station addresses, and both nonces. Address and nonce ordering follows
// IEEE 802.11 so that either side computes the same value.
func DerivePTK(pmk []byte, authenticator, supplicant string, aNonce, sNonce []byte, kdf KDF) ([]byte, error) {
	if len(pmk) == 0 {
		return nil, errors.New("the pairwise master key is empty")
	}
	if len(aNonce) != aNonceLength || len(sNonce) != sNonceLength {
		return nil, fmt.Errorf("nonces must be %d bytes each", aNonceLength)
	}
	lowAddress, highAddress, err := orderAddresses(authenticator, supplicant)
	if err != nil {
		return nil, err
	}
	lowNonce, highNonce, err := orderNonces(aNonce, sNonce)
	if err != nil {
		return nil, err
	}
	seed := make([]byte, 0, 64)
	seed = append(seed, lowAddress...)
	seed = append(seed, highAddress...)
	seed = append(seed, lowNonce...)
	seed = append(seed, highNonce...)
	if kdf == KDFSHA256 {
		// The SHA-256 PRF seeds a 4-byte big-endian length before the label.
		seed = append(seed, 0x00, 0x00, 0x00, byte(len(pairwiseKeyExpansionSHA256)))
	}
	seed = append(seed, pairwiseKeyExpansion(kdf)...)
	return prf(pmk, seed, PTKLengthSHA256, kdf), nil
}

const (
	pairwiseKeyExpansionSHA1   = "Pairwise key expansion"
	pairwiseKeyExpansionSHA256 = "Pairwise key expansion"
)

// KCK returns the key confirmation key, the first 16 bytes of the PTK.
func KCK(ptk []byte) ([]byte, error) {
	if len(ptk) < 16 {
		return nil, errors.New("the pairwise temporal key is too short to contain a KCK")
	}
	return ptk[:16], nil
}

// KeyIV returns the key IV of a message for the address computation that PTK
// derivation needs. It is exported because the KEK and TK layout is verified
// against the observed key IV in tests.
func KeyIV(body []byte) []byte {
	if len(body) < keyIVOffset+keyIVLength {
		return nil
	}
	return append([]byte(nil), body[keyIVOffset:keyIVOffset+keyIVLength]...)
}

// ComputeMIC returns the truncated message integrity code over a captured
// EAPOL-Key message with its own MIC field zeroed. The code covers the
// descriptor type through the end of the key data.
func ComputeMIC(kck, eapolHeader, body []byte, micOffset, micLength int) []byte {
	mac := hmac.New(sha1.New, kck)
	_, _ = mac.Write(eapolHeader)
	zeroed := append([]byte(nil), body...)
	for i := micOffset; i < micOffset+micLength && i < len(zeroed); i++ {
		zeroed[i] = 0
	}
	_, _ = mac.Write(zeroed)
	if micLength <= sha1.Size {
		return mac.Sum(nil)[:micLength]
	}
	return mac.Sum(nil)
}

// VerifyMIC compares a recomputed message integrity code with the one the peer
// transmitted. The comparison is constant time.
func VerifyMIC(kck, eapolHeader, body []byte, micOffset, micLength int) bool {
	transmitted := body[micOffset : micOffset+micLength]
	computed := ComputeMIC(kck, eapolHeader, body, micOffset, micLength)
	if len(transmitted) != len(computed) {
		return false
	}
	return hmac.Equal(transmitted, computed)
}

func (k KDF) hashFunc() func() hash.Hash {
	if k == KDFSHA256 {
		return sha256.New
	}
	return sha1.New
}

// prf is the IEEE 802.11 pseudorandom function. The SHA-256 form prefixes each
// iteration with a 4-byte big-endian counter as the 2020 revision requires.
func prf(key, seed []byte, length int, kdf KDF) []byte {
	out := make([]byte, 0, length)
	var counter uint32
	for len(out) < length {
		mac := hmac.New(kdf.hashFunc(), key)
		if kdf == KDFSHA256 {
			_, _ = mac.Write([]byte{byte(counter >> 24), byte(counter >> 16), byte(counter >> 8), byte(counter)})
		}
		_, _ = mac.Write(seed)
		out = append(out, mac.Sum(nil)...)
		counter++
	}
	return out[:length]
}

// pbkdf2Key implements PBKDF2 with the hash function selected by the KDF so no
// external module is required.
func pbkdf2Key(password, salt []byte, iterations, keyLength int, h func() hash.Hash) ([]byte, error) {
	hashLength := h().Size()
	blocks := (keyLength + hashLength - 1) / hashLength
	out := make([]byte, 0, blocks*hashLength)
	block := make([]byte, 4)
	buffer := make([]byte, hashLength)
	u := make([]byte, hashLength)
	for i := 1; i <= blocks; i++ {
		block[0] = byte(i >> 24)
		block[1] = byte(i >> 16)
		block[2] = byte(i >> 8)
		block[3] = byte(i)
		mac := hmac.New(h, password)
		_, _ = mac.Write(salt)
		_, _ = mac.Write(block)
		copy(buffer, mac.Sum(nil))
		copy(u, buffer)
		for n := 2; n <= iterations; n++ {
			mac.Reset()
			_, _ = mac.Write(u)
			copy(u, mac.Sum(nil))
			for j := range buffer {
				buffer[j] ^= u[j]
			}
		}
		out = append(out, buffer...)
	}
	return out[:keyLength], nil
}

func pairwiseKeyExpansion(kdf KDF) []byte {
	return []byte(pairwiseKeyExpansionSHA1)
}

func orderAddresses(authenticator, supplicant string) (string, string, error) {
	if authenticator == "" || supplicant == "" {
		return "", "", errors.New("both station addresses are required to derive a pairwise temporal key")
	}
	if authenticator < supplicant {
		return authenticator, supplicant, nil
	}
	return supplicant, authenticator, nil
}

func orderNonces(aNonce, sNonce []byte) ([]byte, []byte, error) {
	if len(aNonce) != aNonceLength || len(sNonce) != sNonceLength {
		return nil, nil, fmt.Errorf("nonces must be %d bytes each", aNonceLength)
	}
	if bytesLess(aNonce, sNonce) {
		return aNonce, sNonce, nil
	}
	return sNonce, aNonce, nil
}

func bytesLess(a, b []byte) bool {
	for i := range a {
		if i >= len(b) {
			return false
		}
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// sha1New exposes the SHA-1 constructor for the PBKDF2 test vectors so the
// tests exercise the same code path the KDF selection uses.
func sha1New() hash.Hash { return sha1.New() }

// PutReplayCounter stores a replay counter in an EAPOL-Key body. It exists so a
// test can build a handshake the same way a peer would transmit one.
func PutReplayCounter(body []byte, counter uint64) {
	if len(body) < replayOffset+replayLength {
		return
	}
	binary.BigEndian.PutUint64(body[replayOffset:replayOffset+replayLength], counter)
}

// EAPOLKeyBodyLength returns the total size of an EAPOL-Key body carrying a MIC
// of the given length followed by key data of the given length. A captured body
// is the fixed fields plus the key data, so this is what a receiver observes.
func EAPOLKeyBodyLength(micLength, keyDataLength int) int {
	return micOffset + micLength + 2 + keyDataLength
}
