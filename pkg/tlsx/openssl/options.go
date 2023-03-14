package openssl

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
)

// SupportedTLSVersion of OpenSSL Mode
var SupportedTLSVersions = []string{
	"tls10",
	"tls11",
	"tls12",
	// "tls13",
}

type Protocols int

const (
	TLSv1 Protocols = iota
	TLSv1_1
	TLSv1_2
	TLSv1_3
	DTLSv1
	DTLSv1_2
	TLSUnsupported
)

func (p *Protocols) String() string {
	switch *p {
	case 0:
		return "tls1"
	case 1:
		return "tls1_1"
	case 2:
		return "tls1_2"
	// case 3:
	// 	return "tls1_3"
	case 4:
		return "dtls1"
	case 5:
		return "dtls1_2"
	default:
		return ""
	}
}

func getProtocol(versionTLS string) (Protocols, error) {
	switch versionTLS {
	case "tls10":
		return TLSv1, nil
	case "tls11":
		return TLSv1_1, nil
	case "tls12":
		return TLSv1_2, nil
	// case "tls13":
	// 	tlsversion = TLSv1_3
	// case "dtls10":
	// 	tlsversion = DTLSv1
	// case "dtls12":
	// 	tlsversion = DTLSv1_2
	default:
		return TLSUnsupported, errors.New("unsupported version")
	}
}

// OpenSSL Command Line Options
type Options struct {
	Address       string    // host:port address to connect
	Cipher        []string  // Cipher to use while connecting
	ServerName    string    // Set TLS extension servername in ClientHello (SNI)
	CertChain     bool      // Show Certificate Chain
	Protocol      Protocols // protocol to use
	CAFile        string    // CA Certificate File
	SkipCertParse bool      // SkipCertParse skips parsing and validating certs
}

// generate command Args using given options
func (o *Options) Args() ([]string, error) {
	args := []string{"s_client"}
	if o.Address != "" {
		args = append(args, "-connect", o.Address)
	} else {
		return args, fmt.Errorf("openssl: address missing")
	}

	if len(o.Cipher) != 0 {
		args = append(args, "-cipher", strings.Join(o.Cipher, ","))
	}
	if o.ServerName != "" {
		args = append(args, "-servername", o.ServerName)
	}
	if o.CertChain {
		args = append(args, "-showcerts")
	}

	if o.Protocol.String() != "" {
		args = append(args, "-"+o.Protocol.String())
	}
	if o.CAFile != "" {
		args = append(args, "-CAfile", o.CAFile)
	}

	return args, nil
}

// Session Details returned by openssl
type Session struct {
	Protocol  string
	Cipher    string
	SessionID string
	MasterKey string
}

func (s *Session) getTLSVersion() string {
	switch s.Protocol {
	case "TLSv1":
		return "tls10"
	case "TLSv1.1":
		return "tls11"
	case "TLSv1.2":
		return "tls12"
	// case "TLSv1.3":
	// 	return "tls13"
	default:
		return s.Protocol
	}
}

// Openssl response
type Response struct {
	AllCerts []*x509.Certificate
	Session  *Session
}
