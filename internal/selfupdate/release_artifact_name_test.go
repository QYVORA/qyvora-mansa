package selfupdate

import "testing"

// TestReleaseArtifactName pins the release asset naming for mansa.
//
// macOS is published as "macos" but Go reports GOOS "darwin", and Windows
// assets carry a ".exe" suffix. Android needs no special case: GOOS is
// "android" for a GOOS=android build, so the name resolves to
// "mansa-android-arm64". A linux/arm64 asset is never substituted, because
// Android's bionic linker rejects the ET_EXEC binary a GOOS=linux build makes.
func TestReleaseArtifactName(t *testing.T) {
	tests := []struct {
		goos, goarch, want string
	}{
		{"linux", "amd64", "mansa-linux-amd64"},
		{"linux", "arm64", "mansa-linux-arm64"},
		{"darwin", "amd64", "mansa-macos-amd64"},
		{"darwin", "arm64", "mansa-macos-arm64"},
		{"windows", "amd64", "mansa-windows-amd64.exe"},
		{"windows", "arm64", "mansa-windows-arm64.exe"},
		{"android", "arm64", "mansa-android-arm64"},
	}
	for _, tt := range tests {
		if got := releaseArtifactName("mansa", tt.goos, tt.goarch); got != tt.want {
			t.Errorf("releaseArtifactName(%q, %q) = %q, want %q", tt.goos, tt.goarch, got, tt.want)
		}
	}
}
