package wireless

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestParseInformationElements(t *testing.T) {
	data := []byte{
		0, 4, 'l', 'a', 'b', '1', // SSID
		1, 2, 0x82, 0x84, // supported rates
		3, 1, 11, // DS channel
		50, 1, 0x8c, // extended rate
		48, 20, // RSN IE, 20-byte value
		1, 0, // version
		0, 0x0f, 0xac, 4, // group CCMP-128
		1, 0, 0, 0x0f, 0xac, 4, // one pairwise cipher
		1, 0, 0, 0x0f, 0xac, 8, // one SAE AKM
		0xc0, 0, // PMF capable + required
	}
	got, err := ParseInformationElements(data)
	if err != nil {
		t.Fatal(err)
	}
	if !got.SSIDPresent || got.SSID != "lab1" || got.Channel != 11 {
		t.Fatalf("SSID/channel = %+v", got)
	}
	if len(got.SupportedRates) != 3 || got.SupportedRates[2] != 0x8c {
		t.Fatalf("rates = %v", got.SupportedRates)
	}
	if got.RSN == nil || got.RSN.GroupCipher != "CCMP-128" || got.RSN.AKMSuites[0] != "SAE" || !got.RSN.PMFCapable || !got.RSN.PMFRequired {
		t.Fatalf("RSN = %+v", got.RSN)
	}
}

func TestParseBeaconProbeResponse(t *testing.T) {
	packet := make([]byte, 24+12)
	binary.LittleEndian.PutUint16(packet, uint16(8<<4))
	packet = append(packet, 0, 3, 'a', 'p', '1', 3, 1, 6)
	got, err := ParseBeaconProbeResponse(packet)
	if err != nil {
		t.Fatal(err)
	}
	if got.SSID != "ap1" || got.Channel != 6 {
		t.Fatalf("decoded elements = %+v", got)
	}
	short := make([]byte, 24)
	binary.LittleEndian.PutUint16(short, uint16(8<<4))
	if _, err := ParseBeaconProbeResponse(short); !errors.Is(err, ErrFrameTooShort) {
		t.Fatalf("short beacon error = %v", err)
	}
}

func TestParseInformationElementsRejectsMalformedData(t *testing.T) {
	for _, data := range [][]byte{{0}, {0, 3, 'x'}, {0, 33}} {
		if _, err := ParseInformationElements(data); !errors.Is(err, ErrMalformedInformationElement) {
			t.Errorf("ParseInformationElements(%v) error = %v", data, err)
		}
	}
	badRSN := []byte{48, 2, 1, 0}
	if _, err := ParseInformationElements(badRSN); !errors.Is(err, ErrMalformedRSN) {
		t.Fatalf("malformed RSN error = %v", err)
	}
	truncatedPMKID := []byte{
		1, 0, 0, 0x0f, 0xac, 4,
		1, 0, 0, 0x0f, 0xac, 4,
		1, 0, 0, 0x0f, 0xac, 2,
		0, 0, 1, 0, // capabilities, then one missing PMKID
	}
	if _, err := parseRSN(truncatedPMKID); !errors.Is(err, ErrMalformedRSN) {
		t.Fatalf("truncated PMKID error = %v", err)
	}
}

func TestParseWPAElementDoesNotMisclassifyWEP(t *testing.T) {
	got, err := ParseInformationElements([]byte{221, 4, 0x00, 0x50, 0xf2, 1})
	if err != nil {
		t.Fatal(err)
	}
	if !got.WPA {
		t.Fatal("WPA vendor element was not detected")
	}
	sec := securityFromManagement(ManagementElements{WPA: true, Privacy: true})
	if containsString(sec.Protocols, "WEP") || !containsString(sec.Protocols, "WPA") {
		t.Fatalf("WPA privacy advertisement misclassified: %+v", sec)
	}
}

func TestParseWPSElement(t *testing.T) {
	got, err := ParseInformationElements([]byte{
		221, 4, 0x00, 0x50, 0xf2, 4, // WPS vendor extension
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got.WPS || got.WPA {
		t.Fatalf("WPS/WPA flags = WPS:%v WPA:%v", got.WPS, got.WPA)
	}
	if sec := securityFromManagement(got); !sec.WPS {
		t.Fatalf("WPS flag not preserved in security model: %+v", sec)
	}
}

func FuzzParseInformationElements(f *testing.F) {
	f.Add([]byte{0, 3, 'a', 'p', '1'})
	f.Add([]byte{48, 2, 1, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseInformationElements(data)
	})
}
