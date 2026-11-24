//go:build linux

package app

import "github.com/QYVORA/qyvora-mansa/internal/transport"

func newPlatformBackend() transport.Backend {
	linux := transport.NewLinux()
	if linux.Supported() {
		return linux
	}
	return transport.New()
}
