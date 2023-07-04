package assets

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"

	"github.com/projectdiscovery/gologger"
)

//go:embed root-certs.pem
var rootCertDataBin string

// RootCerts contains root certificates, parsed from rootCertDataBin
var RootCerts []*x509.Certificate

func init() {
	var err error
	RootCerts, err = ParseCertificates([]byte(rootCertDataBin))
	if err != nil {
		gologger.Error().Label("rootcert").Msgf("failed to parse root certs: %v", err)
	}
}

// ParseCertificates parses certificates from data
func ParseCertificates(data []byte) ([]*x509.Certificate, error) {
	var parsedCerts []*x509.Certificate
	var err error
	block, rest := pem.Decode(data)
	for block != nil {
		if block.Type == "CERTIFICATE" {
			cert, errx := x509.ParseCertificate(block.Bytes)
			if errx != nil {
				err = fmt.Errorf("could not parse certificate: %s", errx)
				continue
			}
			parsedCerts = append(parsedCerts, cert)
		}
		if len(rest) == 0 {
			break
		}
		block, rest = pem.Decode(rest)
	}
	return parsedCerts, err
}

// IsRootCert checks if cert is root certificate
func IsRootCert(cert *x509.Certificate) bool {
	for _, c := range RootCerts {
		if c.Equal(cert) {
			return true
		}
	}
	return false
}
