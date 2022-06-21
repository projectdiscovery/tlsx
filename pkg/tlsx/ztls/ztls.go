// Package ztls implements a tls grabbing implementation using
// zmap zcrypto/tls library.
package ztls

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/iputil"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/zmap/zcrypto/tls"
	"github.com/zmap/zcrypto/x509"
)

// Client is a TLS grabbing client using crypto/tls
type Client struct {
	dialer    *fastdialer.Dialer
	tlsConfig *tls.Config
	options   *clients.Options
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
		dialer: options.Fastdialer,
		tlsConfig: &tls.Config{
			CertsOnly:          options.CertsOnly,
			MinVersion:         tls.VersionSSL30,
			MaxVersion:         tls.VersionTLS12,
			InsecureSkipVerify: !options.VerifyServerCertificate,
		},
		options: options,
	}
	if options.ServerName != "" {
		c.tlsConfig.ServerName = options.ServerName
	}
	if len(options.Ciphers) > 0 {
		if customCiphers, err := toZTLSCiphers(options.Ciphers); err != nil {
			return nil, errors.Wrap(err, "could not get ztls ciphers")
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

type timeoutError struct{}

func (timeoutError) Error() string   { return "tls: DialWithDialer timed out" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// Connect connects to a host and grabs the response data
func (c *Client) Connect(hostname, port string) (*clients.Response, error) {
	address := net.JoinHostPort(hostname, port)
	timeout := time.Duration(c.options.Timeout) * time.Second

	var errChannel chan error
	if timeout != 0 {
		errChannel = make(chan error, 2)
		time.AfterFunc(timeout, func() {
			errChannel <- timeoutError{}
		})
	}

	conn, err := c.dialer.Dial(context.Background(), "tcp", address)
	if err != nil {
		return nil, errors.Wrap(err, "could not connect to address")
	}
	var resolvedIP string
	if !iputil.IsIP(hostname) {
		resolvedIP = c.dialer.GetDialedIP(hostname)
	}

	config := c.tlsConfig
	if config.ServerName == "" {
		c := *config
		c.ServerName = hostname
		config = &c
	}

	tlsConn := tls.Client(conn, config)
	if timeout == 0 {
		err = tlsConn.Handshake()
	} else {
		go func() {
			errChannel <- tlsConn.Handshake()
		}()
		err = <-errChannel
	}
	if err == tls.ErrCertsOnly {
		err = nil
	}
	if err != nil {
		conn.Close()
		return nil, errors.Wrap(err, "could not do tls handshake")
	}
	defer tlsConn.Close()

	hl := tlsConn.GetHandshakeLog()

	tlsVersion := versionToTLSVersionString[uint16(hl.ServerHello.Version)]
	tlsCipher := hl.ServerHello.CipherSuite.String()

	response := &clients.Response{
		Timestamp:           time.Now(),
		Host:                hostname,
		IP:                  resolvedIP,
		Port:                port,
		Version:             tlsVersion,
		Cipher:              tlsCipher,
		TLSConnection:       "ztls",
		CertificateResponse: convertCertificateToResponse(parseSimpleTLSCertificate(hl.ServerCertificates.Certificate)),
	}
	if c.options.TLSChain {
		for _, cert := range hl.ServerCertificates.Chain {
			response.Chain = append(response.Chain, convertCertificateToResponse(parseSimpleTLSCertificate(cert)))
		}
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
		SubjectAN:  cert.DNSNames,
		Emails:     cert.EmailAddresses,
		NotBefore:  cert.NotAfter,
		NotAfter:   cert.NotAfter,
		Expired:    clients.IsExpired(cert.NotAfter),
		IssuerDN:   cert.Issuer.String(),
		IssuerCN:   cert.Issuer.CommonName,
		IssuerOrg:  cert.Issuer.Organization,
		SubjectDN:  cert.Subject.String(),
		SubjectCN:  cert.Subject.CommonName,
		SubjectOrg: cert.Subject.Organization,
		FingerprintHash: clients.CertificateResponseFingerprintHash{
			MD5:    clients.MD5Fingerprint(cert.Raw),
			SHA1:   clients.SHA1Fingerprint(cert.Raw),
			SHA256: clients.SHA256Fingerprint(cert.Raw),
		},
	}
}
