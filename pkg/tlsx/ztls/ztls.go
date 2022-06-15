// Package ztls implements a tls grabbing implementation using
// zmap zcrypto/tls library.
package ztls

import (
	"fmt"
	"net"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/zmap/zcrypto/tls"
	"github.com/zmap/zcrypto/x509"
)

// Client is a TLS grabbing client using crypto/tls
type Client struct {
	dialer    *net.Dialer
	tlsConfig *tls.Config
}

// versionStringToTLSVersion converts tls version string to version
var versionStringToTLSVersion = map[string]uint16{
	"ssl30": tls.VersionSSL30,
	"tls10": tls.VersionTLS10,
	"tls11": tls.VersionTLS11,
	"tls12": tls.VersionTLS12,
}

// versionToTLSVersionString converts tls version to version string
var versionToTLSVersionString = map[uint16]string{
	tls.VersionSSL30: "ssl30",
	tls.VersionTLS10: "tls10",
	tls.VersionTLS11: "tls11",
	tls.VersionTLS12: "tls12",
}

// New creates a new grabbing client using crypto/tls
func New(options *clients.Options) (*Client, error) {
	c := &Client{
		dialer: &net.Dialer{
			Timeout: time.Duration(options.Timeout) * time.Second,
		},
		tlsConfig: &tls.Config{
			CertsOnly:          options.CertsOnly,
			MinVersion:         tls.VersionSSL30,
			MaxVersion:         tls.VersionTLS12,
			InsecureSkipVerify: !options.VerifyServerCertificate,
		},
	}
	if options.MinVersion != "" {
		version, ok := versionStringToTLSVersion[options.MinVersion]
		if !ok {
			return nil, fmt.Errorf("invalid min version specified: %s", options.MinVersion)
		} else {
			c.tlsConfig.MinVersion = version
		}
	}
	if options.MaxVersion != "" {
		version, ok := versionStringToTLSVersion[options.MaxVersion]
		if !ok {
			return nil, fmt.Errorf("invalid max version specified: %s", options.MaxVersion)
		} else {
			c.tlsConfig.MaxVersion = version
		}
	}
	return c, nil
}

// Connect connects to a host and grabs the response data
func (c *Client) Connect(hostname, port string) (*clients.Response, error) {
	address := net.JoinHostPort(hostname, port)

	conn, err := c.dialer.Dial("tcp", address)
	if err != nil {
		return nil, errors.Wrap(err, "could not connect to address")
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, c.tlsConfig)
	err = tlsConn.Handshake()
	if err == tls.ErrCertsOnly {
		err = nil
	}
	if err != nil {
		return nil, errors.Wrap(err, "could not do tls handshake")
	}
	hl := tlsConn.GetHandshakeLog()

	tlsVersion := versionToTLSVersionString[uint16(hl.ServerHello.Version)]
	response := &clients.Response{
		Host:    hostname,
		Port:    port,
		Version: tlsVersion,
		Leaf:    convertCertificateToResponse(parseSimpleTLSCertificate(hl.ServerCertificates.Certificate)),
	}
	for _, cert := range hl.ServerCertificates.Chain {
		response.Chain = append(response.Chain, convertCertificateToResponse(parseSimpleTLSCertificate(cert)))
	}
	return response, nil
}

func parseSimpleTLSCertificate(cert tls.SimpleCertificate) *x509.Certificate {
	parsed, _ := x509.ParseCertificate(cert.Raw)
	return parsed
}

func convertCertificateToResponse(cert *x509.Certificate) clients.CertificateResponse {
	if cert == nil {
		return clients.CertificateResponse{}
	}
	return clients.CertificateResponse{
		DNSNames:            cert.DNSNames,
		Emails:              cert.EmailAddresses,
		IssuerCommonName:    cert.Issuer.CommonName,
		IssuerOrganization:  cert.Issuer.Organization,
		SubjectCommonName:   cert.Subject.CommonName,
		SubjectOrganization: cert.Subject.Organization,
	}
}
