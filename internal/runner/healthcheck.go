package runner

import (
	"fmt"
	"net"
	"runtime"
	"strings"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/openssl"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/tls"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/ztls"
	fileutil "github.com/projectdiscovery/utils/file"
)

func DoHealthCheck(flagSet *goflags.FlagSet) string {
	// RW permissions on config file
	cfgFilePath, _ := flagSet.GetConfigFilePath()
	var test strings.Builder
	fmt.Fprintf(&test, "Version: %s\n", version)
	fmt.Fprintf(&test, "Operative System: %s\n", runtime.GOOS)
	fmt.Fprintf(&test, "Architecture: %s\n", runtime.GOARCH)
	fmt.Fprintf(&test, "Go Version: %s\n", runtime.Version())
	fmt.Fprintf(&test, "Compiler: %s\n", runtime.Compiler)

	var testResult string
	ok, err := fileutil.IsReadable(cfgFilePath)
	if ok {
		testResult = "Ok"
	} else {
		testResult = "Ko"
	}
	if err != nil {
		testResult += fmt.Sprintf(" (%s)", err)
	}
	fmt.Fprintf(&test, "Config file \"%s\" Read => %s\n", cfgFilePath, testResult)
	ok, err = fileutil.IsWriteable(cfgFilePath)
	if ok {
		testResult = "Ok"
	} else {
		testResult = "Ko"
	}
	if err != nil {
		testResult += fmt.Sprintf(" (%s)", err)
	}
	fmt.Fprintf(&test, "Config file \"%s\" Write => %s\n", cfgFilePath, testResult)
	c4, err := net.Dial("tcp4", "scanme.sh:80")
	if err == nil && c4 != nil {
		_ = c4.Close()
	}
	testResult = "Ok"
	if err != nil {
		testResult = fmt.Sprintf("Ko (%s)", err)
	}
	fmt.Fprintf(&test, "IPv4 connectivity to scanme.sh:80 => %s\n", testResult)
	c6, err := net.Dial("tcp6", "scanme.sh:80")
	if err == nil && c6 != nil {
		_ = c6.Close()
	}
	testResult = "Ok"
	if err != nil {
		testResult = fmt.Sprintf("Ko (%s)", err)
	}
	fmt.Fprintf(&test, "IPv6 connectivity to scanme.sh:80 => %s\n", testResult)

	test.WriteString("Supported Engines\n")
	test.WriteString("ctls\n")
	fmt.Fprintf(&test, "TLS: %s\n", strings.Join(tls.SupportedTlsVersions, ", "))
	fmt.Fprintf(&test, "Ciphers: %s\n", strings.Join(tls.AllCiphersNames, ", "))

	test.WriteString("ztls\n")
	fmt.Fprintf(&test, "TLS: %s\n", strings.Join(ztls.SupportedTlsVersions, ", "))
	fmt.Fprintf(&test, "Ciphers: %s\n", strings.Join(ztls.AllCiphersNames, ", "))

	if openssl.IsAvailable() {
		test.WriteString("openssl\n")
		fmt.Fprintf(&test, "location: %s\n", openssl.BinaryPath)
	}

	return test.String()
}
