// Package openssl implements a tls grabbing implementation using openssl
package openssl

import (
	"context"
	"crypto/x509"
	"net"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	errorutils "github.com/projectdiscovery/utils/errors"
	iputil "github.com/projectdiscovery/utils/ip"
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
	if (ip != "" && iputil.IsIP(ip)) || c.options.ScanAllIPs || len(c.options.IPVersion) > 0 {
		address = net.JoinHostPort(ip, port)
	} else {
		address = net.JoinHostPort(hostname, port)
	}

	// Note: CLI options are omitted if given value is empty
	opensslOptions := &Options{
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

	// timeout cannot be zero(If GOOS==windows it should be on average 3)
	// this timeout will be used by os.exec context
	if c.options.Timeout < 3 {
		c.options.Timeout = 3
	}

	// validate dialer before using
	if c.dialer == nil {
		var err error
		c.dialer, err = fastdialer.NewDialer(fastdialer.DefaultOptions)
		if err != nil {
			return nil, errorutils.NewWithErr(err).WithTag(PkgTag, "fastdialer").Msgf("failed to create new fastdialer")
		}
	}
	// There is no guarantee that dialed ip is same as ip used by openssl
	// this is only used to avoid inconsistencies
	rawConn, err := c.dialer.Dial(context.TODO(), "tcp", address)
	if err != nil || rawConn == nil {
		return nil, errorutils.NewWithErr(err).WithTag(PkgTag, "fastdialer").Msgf("could not dial address:%v", address)
	}
	defer rawConn.Close()

	resolvedIP, _, err := net.SplitHostPort(rawConn.RemoteAddr().String())
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.TODO(), time.Duration(c.options.Timeout)*time.Second)
	defer cancel()
	// Here _ contains handshake errors and other errors returned by openssl
	resp, errx := getResponse(ctx, opensslOptions)
	if errx != nil {
		return nil, errx.Msgf("failed to response from openssl").WithTag(PkgTag)
	}

	now := time.Now()
	response := &clients.Response{
		Timestamp:           &now,
		Host:                hostname,
		IP:                  resolvedIP,
		ProbeStatus:         true,
		Port:                port,
		Version:             resp.Session.getTLSVersion(),
		CertificateResponse: clients.Convertx509toResponse(hostname, resp.AllCerts[0], c.options.Cert),
		Cipher:              resp.Session.Cipher,
		TLSConnection:       "openssl",
		ServerName:          opensslOptions.ServerName,
	}

	// Note: openssl s_client does not return server certificate if certificate chain is requested
	if c.options.TLSChain {
		responses := []*clients.CertificateResponse{}
		certs := getCertChain(ctx, opensslOptions)
		for _, v := range certs {
			responses = append(responses, clients.Convertx509toResponse(hostname, v, c.options.Cert))
		}
		response.Chain = responses
	}
	return response, nil
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
func getCertChain(ctx context.Context, opts *Options) []*x509.Certificate {
	responses := []*x509.Certificate{}
	opts.CertChain = true
	args, _ := opts.Args()
	result, er := execOpenSSL(ctx, args)
	if er != nil {
		return responses
	}
	certs, err := parseCertificates(result.Stdout)
	if err != nil {
		return responses
	}
	return certs
}
