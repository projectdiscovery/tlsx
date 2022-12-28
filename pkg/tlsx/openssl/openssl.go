// Package openssl implements a tls grabbing implementation using openssl
package openssl

import (
	"context"
	"crypto/x509"
	"net"
	"time"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
)

// Client is a TLS grabbing client using crypto/tls
type Client struct {
	dialer  *fastdialer.Dialer
	options *clients.Options
}

// New creates a new grabbing client using crypto/tls
func New(options *clients.Options) (*Client, error) {
	if !IsAvailable() {
		return nil, ErrNotAvailable
	}
	c := &Client{
		dialer:  options.Fastdialer,
		options: options,
	}
	return c, nil
}

// Connect connects to a host and grabs the response data
func (c *Client) ConnectWithOptions(hostname, ip, port string, options clients.ConnectOptions) (*clients.Response, error) {
	var address string
	if ip != "" || c.options.ScanAllIPs || len(c.options.IPVersion) > 0 {
		address = net.JoinHostPort(ip, port)
	} else {
		address = net.JoinHostPort(hostname, port)
	}

	// Note: CLI options are omitted if given value is empty
	opensslOptions := Options{
		Address:    address,
		ServerName: options.SNI,
		Protocol:   getProtocol(options.VersionTLS),
		CAFile:     c.options.CACertificate,
		Cipher:     validateCiphers(options.Ciphers...),
	}

	if opensslOptions.ServerName == "" {
		// If there are multiple VHOST openssl returns errors unless hostname is specified (ex: projectdiscovery.io)
		opensslOptions.ServerName = hostname
	}

	// timeout cannot be zero
	if c.options.Timeout == 0 {
		c.options.Timeout = 1
	}
	// There is no guarantee that dialed ip is same as ip used by openssl
	// this is only used to avoid inconsistencies
	rawConn, err := c.dialer.Dial(context.TODO(), "tcp", address)
	if err != nil {
		return nil, errors.Wrap(err, "openssl: could not dial address "+address)
	}
	defer rawConn.Close()

	resolvedIP, _, err := net.SplitHostPort(rawConn.RemoteAddr().String())
	if err != nil {
		return nil, err
	}
	args, err := opensslOptions.Args()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.TODO(), time.Duration(c.options.Timeout)*time.Second)
	defer cancel()
	// Here _ contains handshake errors and other errors returned by openssl
	bin, _, err := execOpenSSL(ctx, args)
	if err != nil {
		return nil, err
	}
	resp, err := readResponse(bin)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	response := &clients.Response{
		Timestamp:           &now,
		Host:                hostname,
		IP:                  resolvedIP,
		ProbeStatus:         true,
		Port:                port,
		Version:             resp.Session.getTLSVersion(),
		CertificateResponse: c.convertCertificateToResponse(hostname, resp.AllCerts[0]),
		Cipher:              resp.Session.Cipher,
		TLSConnection:       "openssl",
		ServerName:          opensslOptions.ServerName,
	}

	// Note: openssl s_client does not return server certificate if certificate chain is requested
	if c.options.TLSChain {
		responses := []*clients.CertificateResponse{}
		certs := getCertChain(ctx, opensslOptions)
		for _, v := range certs {
			responses = append(responses, c.convertCertificateToResponse(hostname, v))
		}
		response.Chain = responses
	}
	return response, nil
}

// same as tls
func (c *Client) convertCertificateToResponse(hostname string, cert *x509.Certificate) *clients.CertificateResponse {
	response := &clients.CertificateResponse{
		SubjectAN:    cert.DNSNames,
		Emails:       cert.EmailAddresses,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		Expired:      clients.IsExpired(cert.NotAfter),
		SelfSigned:   clients.IsSelfSigned(cert.AuthorityKeyId, cert.SubjectKeyId),
		MisMatched:   clients.IsMisMatchedCert(hostname, append(cert.DNSNames, cert.Subject.CommonName)),
		Revoked:      clients.IsTLSRevoked(cert),
		WildCardCert: clients.IsWildCardCert(append(cert.DNSNames, cert.Subject.CommonName)),
		IssuerCN:     cert.Issuer.CommonName,
		IssuerOrg:    cert.Issuer.Organization,
		SubjectCN:    cert.Subject.CommonName,
		SubjectOrg:   cert.Subject.Organization,
		FingerprintHash: clients.CertificateResponseFingerprintHash{
			MD5:    clients.MD5Fingerprint(cert.Raw),
			SHA1:   clients.SHA1Fingerprint(cert.Raw),
			SHA256: clients.SHA256Fingerprint(cert.Raw),
		},
	}
	response.IssuerDN = clients.ParseASN1DNSequenceWithZpkixOrDefault(cert.RawIssuer, cert.Issuer.String())
	response.SubjectDN = clients.ParseASN1DNSequenceWithZpkixOrDefault(cert.RawSubject, cert.Subject.String())
	if c.options.Cert {
		response.Certificate = clients.PemEncode(cert.Raw)
	}
	return response
}

// SupportedTLSVersions is meaningless here but necessary due to the interface system implemented
func (c *Client) SupportedTLSVersions() ([]string, error) {
	return supportedTLSVersions(), nil
}

// SupportedTLSVersions is meaningless here but necessary due to the interface system implemented
func (c *Client) SupportedTLSCiphers() ([]string, error) {
	return fetchCiphers(), nil
}

// Openssl s_client does not dump certificate chain unless specified
// and if specified does not dump server certificate
func getCertChain(ctx context.Context, opts Options) []*x509.Certificate {
	responses := []*x509.Certificate{}
	opts.CertChain = true
	args, _ := opts.Args()
	bin, _, er := execOpenSSL(ctx, args)
	if er != nil {
		return responses
	}
	certs, err := parseCertificates(bin)
	if err != nil {
		return responses
	}
	return certs
}
