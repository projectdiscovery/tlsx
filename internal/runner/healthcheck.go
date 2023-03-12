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
	test.WriteString(fmt.Sprintf("Version: %s\n", version))
	test.WriteString(fmt.Sprintf("Operative System: %s\n", runtime.GOOS))
	test.WriteString(fmt.Sprintf("Architecture: %s\n", runtime.GOARCH))
	test.WriteString(fmt.Sprintf("Go Version: %s\n", runtime.Version()))
	test.WriteString(fmt.Sprintf("Compiler: %s\n", runtime.Compiler))

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
	test.WriteString(fmt.Sprintf("Config file \"%s\" Read => %s\n", cfgFilePath, testResult))
	ok, err = fileutil.IsWriteable(cfgFilePath)
	if ok {
		testResult = "Ok"
	} else {
		testResult = "Ko"
	}
	if err != nil {
		testResult += fmt.Sprintf(" (%s)", err)
	}
	test.WriteString(fmt.Sprintf("Config file \"%s\" Write => %s\n", cfgFilePath, testResult))
	c4, err := net.Dial("tcp4", "scanme.sh:80")
	if err == nil && c4 != nil {
		c4.Close()
	}
	testResult = "Ok"
	if err != nil {
		testResult = fmt.Sprintf("Ko (%s)", err)
	}
	test.WriteString(fmt.Sprintf("IPv4 connectivity to scanme.sh:80 => %s\n", testResult))
	c6, err := net.Dial("tcp6", "scanme.sh:80")
	if err == nil && c6 != nil {
		c6.Close()
	}
	testResult = "Ok"
	if err != nil {
		testResult = fmt.Sprintf("Ko (%s)", err)
	}
	test.WriteString(fmt.Sprintf("IPv6 connectivity to scanme.sh:80 => %s\n", testResult))

	test.WriteString("Supported Engines\n")
	test.WriteString("ctls\n")
	test.WriteString(fmt.Sprintf("TLS: %s\n", strings.Join(tls.SupportedTlsVersions, ", ")))
	test.WriteString(fmt.Sprintf("Ciphers: %s\n", strings.Join(tls.AllCiphersNames, ", ")))

	test.WriteString("ztls\n")
	test.WriteString(fmt.Sprintf("TLS: %s\n", strings.Join(ztls.SupportedTlsVersions, ", ")))
	test.WriteString(fmt.Sprintf("Ciphers: %s\n", strings.Join(ztls.AllCiphersNames, ", ")))

	if openssl.IsAvailable() {
		test.WriteString("openssl\n")
		test.WriteString(fmt.Sprintf("location: %s\n", openssl.BinaryPath))
	}

	return test.String()
}
