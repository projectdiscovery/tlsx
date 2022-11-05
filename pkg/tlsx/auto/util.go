package auto

import (
	"github.com/projectdiscovery/tlsx/pkg/tlsx/tls"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/ztls"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

var (
	allCiphersNames      []string
	supportedTlsVersions []string
)

func init() {
	allCiphersNames = append(tls.AllCiphersNames, ztls.AllCiphersNames...)
	supportedTlsVersions = append(tls.SupportedTlsVersions, ztls.SupportedTlsVersions...)
	allCiphersNames = sliceutil.Dedupe(allCiphersNames)
	supportedTlsVersions = sliceutil.Dedupe(supportedTlsVersions)
}
