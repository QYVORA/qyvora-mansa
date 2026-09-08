// Package version holds build identity for the mansa binary.
//
// Values are compile-time defaults; release builds stamp them via:
//
//	go build -ldflags "-X github.com/QYVORA/qyvora-mansa/internal/version.Version=<tag> ..."
package version

var (
	Version   = "dev"
	Commit    = "none"
	Date      = "unknown"
	BuildUser = "unknown"
)

// String returns a formatted version block.
func String() string {
	return "mansa " + Version + "\n  Commit:  " + Commit + "\n  Built:   " + Date + "\n  User:    " + BuildUser
}
