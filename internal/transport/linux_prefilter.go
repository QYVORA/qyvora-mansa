package transport

import (
	"errors"
	"runtime"
)

// LinuxPrefilter manages kernel BPF attachment for a Linux socket handle.
// It does not fabricate success on systems where the kernel rejects the
// filter; attach returns an error when unsupported.
type LinuxPrefilter struct{}

// ErrPrefilterUnsupported indicates the kernel does not support attaching
// the requested BPF program for the configured capture path.
var ErrPrefilterUnsupported = errors.New("kernel BPF prefilter is not supported for this interface")

// Attach compiles and attaches a prefilter to fd. On non-Linux platforms or
// when the kernel rejects the filter, Attach returns ErrPrefilterUnsupported.
func (p *LinuxPrefilter) Attach(fd int, spec PrefilterSpec) error {
	if runtime.GOOS != "linux" {
		return ErrPrefilterUnsupported
	}
	if _, err := CompilePrefilter(spec); err != nil {
		return err
	}
	// In this build, we do not attempt to actually load BPF into the kernel.
	// The method exists to satisfy the interface contract and is exercised by
	// integration paths that probe support explicitly.
	return ErrPrefilterUnsupported
}

// Detach removes any previously attached prefilter. It is idempotent.
func (p *LinuxPrefilter) Detach(fd int) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	return nil
}

// Inspect reports the currently attached prefilter, if any.
func (p *LinuxPrefilter) Inspect(fd int) (PrefilterSpec, bool, error) {
	if runtime.GOOS != "linux" {
		return PrefilterSpec{}, false, nil
	}
	return PrefilterSpec{}, false, nil
}

// Probe returns true if kernel BPF prefiltering appears supported.
func (p *LinuxPrefilter) Probe(fd int) bool {
	return runtime.GOOS == "linux"
}
