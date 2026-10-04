package transport

import (
	"errors"
	"runtime"
)

var ErrPrefilterUnsupported = errors.New("kernel BPF prefilter is not supported for this interface")

type LinuxPrefilter struct{}

func (p *LinuxPrefilter) Attach(fd int, spec PrefilterSpec) error {
	if runtime.GOOS != "linux" {
		return ErrPrefilterUnsupported
	}
	if _, err := CompilePrefilter(spec); err != nil {
		return err
	}
	return ErrPrefilterUnsupported
}

func (p *LinuxPrefilter) Detach(fd int) error {
	return nil
}

func (p *LinuxPrefilter) Inspect(fd int) (PrefilterSpec, bool, error) {
	return PrefilterSpec{}, false, nil
}

func (p *LinuxPrefilter) Probe(fd int) bool {
	return runtime.GOOS == "linux"
}
