//go:build !linux

package app

import "github.com/QYVORA/qyvora-mansa/internal/transport"

func newPlatformBackend() transport.Backend {
	return transport.New()
}
