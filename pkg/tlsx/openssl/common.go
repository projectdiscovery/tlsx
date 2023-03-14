package openssl

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/projectdiscovery/gologger"
	errorutils "github.com/projectdiscovery/utils/errors"
)

var (
	ErrParse          = errorutils.NewWithTag("openssl", "failed to parse openssl response")
	ErrCertParse      = errorutils.NewWithTag("openssl", "failed to parse server certificate")
	ErrNotImplemented = errorutils.NewWithTag("openssl", "feature not implemented")
	ErrNotAvailable   = errorutils.NewWithTag("openssl", "executable not installed or in PATH")
	ErrNoSession      = errorutils.NewWithTag("openssl", "session not created/found")
)

var (
	BinaryPath   = ""
	OPENSSL_CONF = ""
	IsLibreSSL   = false
	PkgTag       = "" // Header or Tag value that will be reflected in all errors (include openssl(libressl) and version)
)

// Certain distro provide openssl config with different min protocol version ex: Ubuntu 18,19,20 etc
// In such case temporary override using a temp file with below config
// this temporary override is only done to openssl and not `LibreSSL`(due to certain inconsistencies)
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
	if BinaryPath == "" {
		// not available or failed to get return
		gologger.Debug().Label("openssl").Msgf("openssl binary not found skipping")
		return
	}
	if err := openSSLSetup(); err != nil {
		gologger.Debug().Label("openssl").Msgf(err.Error())
	}
}

// fetch openssl version
func openSSLSetup() errorutils.Error {
	result, err := execOpenSSL(context.TODO(), []string{"version"})
	if err != nil {
		return errorutils.NewWithErr(err).WithTag("openssl").Msgf(result.Stderr)
	}
	arr := strings.Fields(result.Stdout)
	if len(arr) < 2 {
		return errorutils.NewWithTag("openssl", "failed to parse openssl version got %v", result.Stdout)
	}
	if arr[0] == "LibreSSL" {
		IsLibreSSL = true
	}
	// else assume given is openssl
	OpenSSLVersion := arr[1]
	// This config is only valid for openssl and not "LibreSSL"
	if !IsLibreSSL {
		OPENSSL_CONF = filepath.Join(os.TempDir(), "openssl.cnf")
		err := os.WriteFile(OPENSSL_CONF, []byte(openSSLConfig), 0600)
		if err != nil {
			gologger.Debug().Label("openssl").Msgf("Failed to create openssl.cnf file")
			OPENSSL_CONF = ""
		}
		PkgTag = "OpenSSL" + OpenSSLVersion
	} else {
		PkgTag = "LibreSSL" + OpenSSLVersion
	}

	return nil
}

// check if openssl if available for use
func IsAvailable() bool {
	return BinaryPath != ""
}

// UseOpenSSLBinary From Path
func UseOpenSSLBinary(binpath string) {
	BinaryPath = binpath
	if err := openSSLSetup(); err != nil {
		// do not fallback
		gologger.Fatal().Label("openssl").Msgf(err.Error())
	}
}
