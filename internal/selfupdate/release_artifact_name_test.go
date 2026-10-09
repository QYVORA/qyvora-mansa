package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

// TestReleaseArtifactName pins the release asset naming for mansa.
//
// Canonical: mansa_<version>_<linux|macos|windows|android>_<arch>.tar.gz
// (zip on windows), where <version> is the tag with its leading "v" stripped.
//
// macOS is published as "macos" but Go reports GOOS "darwin". Android needs no
// special case: GOOS is "android" for a GOOS=android build, so the name
// resolves to "mansa_<version>_android_arm64.tar.gz". A linux/arm64 asset is
// never substituted, because Android's bionic linker rejects the ET_EXEC
// binary a GOOS=linux build makes.
func TestReleaseArtifactName(t *testing.T) {
	tests := []struct {
		version, goos, goarch, want string
	}{
		{"v0.1.0", "linux", "amd64", "mansa_0.1.0_linux_amd64.tar.gz"},
		{"v0.1.0", "linux", "arm64", "mansa_0.1.0_linux_arm64.tar.gz"},
		{"v0.1.0", "darwin", "amd64", "mansa_0.1.0_macos_amd64.tar.gz"},
		{"v0.1.0", "darwin", "arm64", "mansa_0.1.0_macos_arm64.tar.gz"},
		{"v0.1.0", "windows", "amd64", "mansa_0.1.0_windows_amd64.zip"},
		{"v0.1.0", "windows", "arm64", "mansa_0.1.0_windows_arm64.zip"},
		{"v0.1.0", "android", "arm64", "mansa_0.1.0_android_arm64.tar.gz"},
		{"0.1.0", "linux", "amd64", "mansa_0.1.0_linux_amd64.tar.gz"},
	}
	for _, tt := range tests {
		got := releaseArtifactName(tt.version, "mansa", tt.goos, tt.goarch)
		if got != tt.want {
			t.Errorf("releaseArtifactName(%q, mansa, %q, %q) = %q, want %q",
				tt.version, tt.goos, tt.goarch, got, tt.want)
		}
	}
}

// TestReleaseArtifactNameStripsVersionPrefix guards the specific bug this
// contract exists for: leaving the "v" on produces a name no release published.
func TestReleaseArtifactNameStripsVersionPrefix(t *testing.T) {
	for _, tag := range []string{"v0.1.0", "V0.1.0", "0.1.0"} {
		got := releaseArtifactName(tag, "mansa", "linux", "amd64")
		if strings.Contains(got, "_v0.1.0_") || strings.Contains(got, "_V0.1.0_") {
			t.Errorf("releaseArtifactName(%q, mansa, linux, amd64) = %q, kept the version prefix", tag, got)
		}
	}
}

// TestExtractBinaryRoundTrip proves the updater installs the executable entry
// rather than the archive bytes: a tar.gz containing "mansa" extracts to that
// payload.
func TestExtractBinaryRoundTrip(t *testing.T) {
	payload := []byte("mansa-binary")
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "mansa", Mode: 0o755, Size: int64(len(payload))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	_ = gz.Close()

	got, err := extractBinary(buf.Bytes(), "mansa_0.1.0_linux_amd64.tar.gz", "mansa")
	if err != nil {
		t.Fatalf("extractBinary: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("extracted %q, want %q", got, payload)
	}
}
