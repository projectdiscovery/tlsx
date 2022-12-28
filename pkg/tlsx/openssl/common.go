package openssl

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
)

var (
	ErrParse          = errors.New("openssl: failed to parse openssl response")
	ErrCertParse      = errors.New("openssl: failed to parse server certificate")
	ErrNotImplemented = errors.New("openssl: feature not implemented")
	ErrNotAvailable   = errors.New("openssl: executable not installed or in PATH")
	ErrNoSession      = errors.New("openssl: session not created/found")
)

var BinaryPath, OpenSSL_CONF string

// Certain distro provide openssl config with different min protocol version ex: Ubuntu 18,19,20 etc
// In such case temporary overrride using a temp file with below config
var openSSLConfig string = `openssl_conf = default_conf

[ default_conf ]
ssl_conf = ssl_sect

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
MinProtocol = SSLv3
CipherString = DEFAULT:@SECLEVEL=1
`

func init() {
	if runtime.GOOS == "windows" {
		BinaryPath, _ = exec.LookPath("openssl.exe")
	} else {
		BinaryPath, _ = exec.LookPath("openssl")
	}
	OpenSSL_CONF = filepath.Join(os.TempDir(), "openssl.cnf")
	err := os.WriteFile(OpenSSL_CONF, []byte(openSSLConfig), 0644)
	if err != nil {
		gologger.Debug().Label("openssl").Msgf("Failed to create openssl.cnf file")
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
