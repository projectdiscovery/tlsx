package openssl

import (
	"os/exec"
	"runtime"

	"github.com/pkg/errors"
)

var (
	ErrParse          = errors.New("openssl: failed to parse openssl response")
	ErrCertParse      = errors.New("openssl: failed to parse server certificate")
	ErrNotImplemented = errors.New("openssl: feature not implemented")
	ErrNotAvailable   = errors.New("openssl executable not installed or in PATH")
	ErrNoSession      = errors.New("openssl: session not created/found")
)

var BinaryPath string

func init() {
	if runtime.GOOS == "windows" {
		BinaryPath, _ = exec.LookPath("openssl.exe")
	} else {
		BinaryPath, _ = exec.LookPath("openssl")
	}
}

// check if openssl if available for use
func IsAvailable() bool {
	if BinaryPath != "" {
		return true
	} else {
		return false
	}
}
