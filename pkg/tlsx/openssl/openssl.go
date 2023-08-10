// Package openssl implements a tls grabbing implementation using openssl
package openssl

import (
	"context"
	"crypto/x509"
	"net"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/tlsx/pkg/output/stats"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	errorutils "github.com/projectdiscovery/utils/errors"
	iputil "github.com/projectdiscovery/utils/ip"
	stringsutil "github.com/projectdiscovery/utils/strings"
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
	opensslOpts, errx := c.getOpenSSLopts(hostname, ip, port, options)
	if errx != nil {
		return nil, errx.Msgf("failed to generate openssl options")
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
	rawConn, err := c.dialer.Dial(context.TODO(), "tcp", opensslOpts.Address)
	if err != nil || rawConn == nil {
		return nil, errorutils.NewWithErr(err).WithTag(PkgTag, "fastdialer").Msgf("could not dial address:%v", opensslOpts.Address)
	}
	defer rawConn.Close()

	resolvedIP, _, err := net.SplitHostPort(rawConn.RemoteAddr().String())
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.TODO(), time.Duration(c.options.Timeout)*time.Second)
	defer cancel()
	// Here _ contains handshake errors and other errors returned by openssl
	resp, errx := getResponse(ctx, opensslOpts)
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
		CertificateResponse: clients.Convertx509toResponse(c.options, hostname, resp.AllCerts[0], c.options.Cert),
		Cipher:              resp.Session.Cipher,
		TLSConnection:       "openssl",
		ServerName:          opensslOpts.ServerName,
	}
	certs := getCertChain(ctx, opensslOpts)
	response.Untrusted = clients.IsUntrustedCA(certs)

	// Note: openssl s_client does not return server certificate if certificate chain is requested
	if c.options.TLSChain {
		responses := []*clients.CertificateResponse{}
		for _, v := range certs {
			responses = append(responses, clients.Convertx509toResponse(c.options, hostname, v, c.options.Cert))
		}
		response.Chain = responses
	}
	return response, nil
}

// EnumerateCiphers enumerates all supported ciphers of openssl on target
func (c *Client) EnumerateCiphers(hostname, ip, port string, options clients.ConnectOptions) ([]string, error) {
	// filter ciphers based on given seclevel
	toEnumerate := clients.GetCiphersWithLevel(AllCiphersNames, options.CipherLevel...)

	enumeratedCiphers := []string{}

	// generate openssl options
	opensslOpts, err := c.getOpenSSLopts(hostname, ip, port, options)
	if err != nil {
		return nil, err.Msgf("failed to generate openssl options")
	}
	opensslOpts.SkipCertParse = true
	gologger.Debug().Label(PkgTag).Msgf("Starting cipher enumeration with %v ciphers in %v", len(toEnumerate), options.VersionTLS)

	for _, v := range toEnumerate {
		opensslOpts.Cipher = []string{v}
		stats.IncrementOpensslTLSConnections()
		if resp, errx := getResponse(context.TODO(), opensslOpts); errx == nil && resp.Session.Cipher != "0000" {
			// 0000 indicates handshake failure
			enumeratedCiphers = append(enumeratedCiphers, resp.Session.Cipher)
		}
	}
	return enumeratedCiphers, nil
}

// SupportedTLSVersions is meaningless here but necessary due to the interface system implemented
func (c *Client) SupportedTLSVersions() ([]string, error) {
	return SupportedTLSVersions, nil
}

// SupportedTLSVersions is meaningless here but necessary due to the interface system implemented
func (c *Client) SupportedTLSCiphers() ([]string, error) {
	return AllCiphersNames, nil
}

func (c *Client) getOpenSSLopts(hostname, ip, port string, options clients.ConnectOptions) (*Options, errorutils.Error) {
	var protocolVersion string
	switch {
	case options.VersionTLS != "":
		protocolVersion = options.VersionTLS
	case c.options.MinVersion != "":
		protocolVersion = c.options.MinVersion
	case c.options.MaxVersion != "":
		protocolVersion = c.options.MaxVersion
	default:
		protocolVersion = "tls12"
	}
	protocol, err := getProtocol(protocolVersion)
	if err != nil {
		return nil, errorutils.NewWithTag("openssl", err.Error())
	}

	// Note: CLI options are omitted if given value is empty
	opensslOptions := &Options{
		ServerName: options.SNI,
		Protocol:   protocol,
		CAFile:     c.options.CACertificate,
	}
	if (ip != "" && iputil.IsIP(ip)) || c.options.ScanAllIPs || len(c.options.IPVersion) > 0 {
		opensslOptions.Address = net.JoinHostPort(ip, port)
	} else {
		opensslOptions.Address = net.JoinHostPort(hostname, port)
	}
	// validation
	if (hostname == "" && ip == "") || port == "" {
		return nil, errorutils.NewWithTag("openssl", "client requires valid address got port=%v,hostname=%v,ip=%v", port, hostname, ip)
	}

	// In enum mode return if given options are not supported
	if options.EnumMode == clients.Version && (options.VersionTLS == "" || !stringsutil.EqualFoldAny(options.VersionTLS, SupportedTLSVersions...)) {
		// version not supported
		return nil, errorutils.NewWithTag("openssl", "tlsversion `%v` not supported in openssl", options.VersionTLS)
	}
	if options.EnumMode != clients.Cipher {
		ciphers, err := toOpenSSLCiphers(options.Ciphers...)
		if err != nil {
			return nil, errorutils.NewWithErr(err).WithTag("openssl")
		}
		opensslOptions.Cipher = ciphers
		if opensslOptions.ServerName == "" {
			// If there are multiple VHOST openssl returns errors unless hostname is specified (ex: projectdiscovery.io)
			opensslOptions.ServerName = hostname
		}
	} else {
		if !stringsutil.EqualFoldAny(options.VersionTLS, SupportedTLSVersions...) {
			return nil, errorutils.NewWithTag(PkgTag, "cipher enum with version %v not implemented", options.VersionTLS)
		}
	}
	return opensslOptions, nil
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
