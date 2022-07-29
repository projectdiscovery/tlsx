//go:build (linux || darwin) && openssl

// Package openssl implements a tls grabbing implementation using openssl
package openssl

import (
	"context"
	"encoding/pem"
	"io/ioutil"
	"net"
	"strings"
	"time"

	"github.com/zmap/zcrypto/x509"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/iputil"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/ztls"
	"github.com/spacemonkeygo/openssl"
)

// Client is a TLS grabbing client using crypto/tls
type Client struct {
	dialer           *fastdialer.Dialer
	openSSLDialFlags []openssl.DialFlags
	options          *clients.Options
}

// New creates a new grabbing client using crypto/tls
func New(options *clients.Options) (*Client, error) {
	c := &Client{
		dialer:  options.Fastdialer,
		options: options,
	}

	if !options.VerifyServerCertificate {
		c.openSSLDialFlags = append(c.openSSLDialFlags, openssl.InsecureSkipHostVerification)
	}

	return c, nil
}

func (c *Client) OpenSSLDialFlags() openssl.DialFlags {
	if len(c.openSSLDialFlags) == 0 {
		return 0
	}
	initialFlag := c.openSSLDialFlags[0]
	allDialFlags := initialFlag
	for _, dialFlag := range c.openSSLDialFlags {
		if dialFlag != initialFlag {
			allDialFlags = allDialFlags & dialFlag
		}
	}
	return allDialFlags
}

// Connect connects to a host and grabs the response data
func (c *Client) ConnectWithOptions(hostname, ip, port string, options clients.ConnectOptions) (*clients.Response, error) {
	address := net.JoinHostPort(hostname, port)

	if c.options.ScanAllIPs || len(c.options.IPVersion) > 0 {
		address = net.JoinHostPort(ip, port)
	}

	opensslCtx, err := openssl.NewCtx()
	if err != nil {
		return nil, err
	}

	if c.options.Timeout > 0 {
		opensslCtx.SetTimeout(time.Duration(c.options.Timeout) * time.Second)
	}

	if len(c.options.Ciphers) > 0 {
		if err := opensslCtx.SetCipherList(strings.Join(c.options.Ciphers, ",")); err != nil {
			return nil, errors.Wrap(err, "could not set ciphers")
		}
	}

	if c.options.CACertificate != "" {
		caCert, err := ioutil.ReadFile(c.options.CACertificate)
		if err != nil {
			return nil, errors.Wrap(err, "could not read ca certificate")
		}
		caStore := opensslCtx.GetCertificateStore()
		err = caStore.LoadCertificatesFromPEM(caCert)
		if err != nil {
			return nil, errors.Wrap(err, "could not add certificate to store")
		}
	}

	ctx := context.Background()
	if c.options.Timeout != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(c.options.Timeout)*time.Second)
		defer cancel()
	}

	rawConn, err := c.dialer.Dial(ctx, "tcp", address)
	if err != nil {
		return nil, errors.Wrap(err, "could not dial address")
	}
	defer rawConn.Close()

	var resolvedIP string
	if !iputil.IsIP(hostname) {
		resolvedIP = c.dialer.GetDialedIP(hostname)
		if resolvedIP == "" {
			resolvedIP = ip
		}
	}

	conn, err := openssl.Client(rawConn, opensslCtx)
	if err != nil {
		return nil, errors.Wrap(err, "could not wrap raw conn")
	}
	defer conn.Close()

	if options.SNI != "" {
		if err := conn.SetTlsExtHostName(options.SNI); err != nil {
			return nil, errors.New("could not set custom SNI")
		}
	}

	// ignoring handshake errors
	_ = conn.Handshake()

	peerCertificates, err := conn.PeerCertificateChain()
	if err != nil {
		return nil, errors.Wrap(err, "could not get peer certificates")
	}

	if len(peerCertificates) == 0 {
		return nil, errors.New("no certificates returned by server")
	}

	tlsCipher, err := conn.CurrentCipher()
	if err != nil {
		return nil, errors.Wrap(err, "could not get current cipher")
	}

	leafCertificate := peerCertificates[0]
	certificateChain := peerCertificates[1:]
	serverName := conn.GetServername()

	x509LeafCertificate, err := c.convertOpenSSLToX509Certificate(leafCertificate)
	if err != nil {
		return nil, errors.Wrap(err, "could not convert openssl leaf certificate")
	}

	now := time.Now()
	response := &clients.Response{
		Timestamp:           &now,
		Host:                hostname,
		IP:                  resolvedIP,
		ProbeStatus:         true,
		Port:                port,
		Cipher:              tlsCipher,
		TLSConnection:       "openssl",
		CertificateResponse: ztls.ConvertCertificateToResponse(c.options, hostname, x509LeafCertificate),
		ServerName:          serverName,
	}
	if c.options.TLSChain {
		for _, opensslCert := range certificateChain {
			x509Cert, err := c.convertOpenSSLToX509Certificate(opensslCert)
			if err != nil {
				return nil, errors.Wrap(err, "could not convert openssl chain certificate")
			}
			response.Chain = append(response.Chain, ztls.ConvertCertificateToResponse(c.options, hostname, x509Cert))
		}
	}
	return response, nil
}

func (c *Client) convertOpenSSLToX509Certificate(opensslCert *openssl.Certificate) (*x509.Certificate, error) {
	pemBytes, err := opensslCert.MarshalPEM()
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal openssl to pem x509")
	}
	pemBlock, _ := pem.Decode(pemBytes)
	if err != nil {
		return nil, errors.Wrap(err, "could not read openssl pem x509 to go pem")
	}
	if pemBlock.Type != "CERTIFICATE" {
		return nil, errors.Wrap(err, "unsupported pem block type")
	}
	x509Certificate, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "could not convert openssl x509 to go x509")
	}

	return x509Certificate, nil
}
