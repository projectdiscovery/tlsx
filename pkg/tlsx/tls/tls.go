// Package tls implements a tls grabbing implementation using
// standard package crypto/tls library.
package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
)

// Client is a TLS grabbing client using crypto/tls
type Client struct {
	dialer    *net.Dialer
	tlsConfig *tls.Config
}

// versionStringToTLSVersion converts tls version string to version
var versionStringToTLSVersion = map[string]uint16{
	"tls10": tls.VersionTLS10,
	"tls11": tls.VersionTLS11,
	"tls12": tls.VersionTLS12,
	"tls13": tls.VersionTLS13,
}

// versionToTLSVersionString converts tls version to version string
var versionToTLSVersionString = map[uint16]string{
	tls.VersionTLS10: "tls10",
	tls.VersionTLS11: "tls11",
	tls.VersionTLS12: "tls12",
	tls.VersionTLS13: "tls13",
}

// New creates a new grabbing client using crypto/tls
func New(options *clients.Options) (*Client, error) {
	c := &Client{
		dialer: &net.Dialer{
			Timeout: time.Duration(options.Timeout) * time.Second,
		},
		tlsConfig: &tls.Config{
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
			InsecureSkipVerify: !options.VerifyServerCertificate,
		},
	}
	if len(options.Ciphers) > 0 {
		if customCiphers, err := toTLSCiphers(options.Ciphers); err != nil {
			return nil, errors.Wrap(err, "could not get tls ciphers")
		} else {
			c.tlsConfig.CipherSuites = customCiphers
		}
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

	conn, err := tls.DialWithDialer(c.dialer, "tcp", address, c.tlsConfig)
	if err != nil {
		return nil, errors.Wrap(err, "could not dial address")
	}
	defer conn.Close()

	connectionState := conn.ConnectionState()
	if len(connectionState.PeerCertificates) == 0 {
		return nil, errors.New("no certificates returned by server")
	}
	tlsVersion := versionToTLSVersionString[connectionState.Version]

	leafCertificate := connectionState.PeerCertificates[0]
	certificateChain := connectionState.PeerCertificates[1:]

	response := &clients.Response{
		Host:    hostname,
		Port:    port,
		Version: tlsVersion,
		Leaf:    convertCertificateToResponse(leafCertificate),
	}
	for _, cert := range certificateChain {
		response.Chain = append(response.Chain, convertCertificateToResponse(cert))
	}
	return response, nil
}

func convertCertificateToResponse(cert *x509.Certificate) clients.CertificateResponse {
	return clients.CertificateResponse{
		DNSNames:            cert.DNSNames,
		Emails:              cert.EmailAddresses,
		IssuerCommonName:    cert.Issuer.CommonName,
		IssuerOrganization:  cert.Issuer.Organization,
		SubjectCommonName:   cert.Subject.CommonName,
		SubjectOrganization: cert.Subject.Organization,
	}
}
