// Package ztls implements a tls grabbing implementation using
// zmap zcrypto/tls library.
package ztls

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/tlsx/pkg/output/stats"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/ztls/ja3"
	"github.com/projectdiscovery/utils/conn/connpool"
	errorutil "github.com/projectdiscovery/utils/errors"
	iputil "github.com/projectdiscovery/utils/ip"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/rs/xid"
	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/tls"
	"github.com/zmap/zcrypto/x509"
)

func init() {
	asn1.AllowPermissiveParsing = true
}

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

	if len(options.Ciphers) > 0 {
		if customCiphers, err := toZTLSCiphers(options.Ciphers); err != nil {
			return nil, errorutil.NewWithTag("ztls", "could not get ztls ciphers").Wrap(err)
		} else {
			c.tlsConfig.CipherSuites = customCiphers
		}
	} else {
		// unless explicitly specified client should advertise all supported ciphers
		// Note: Go stdlib by default only advertises a safe/default list of ciphers
		c.tlsConfig.CipherSuites = AllCiphers
	}
	if options.CACertificate != "" {
		caCert, err := os.ReadFile(options.CACertificate)
		if err != nil {
			return nil, errorutil.NewWithTag("ztls", "could not read ca certificate").Wrap(err)
		}
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caCert) {
			gologger.Error().Msgf("Could not append parsed ca-cert to config!")
		}
		c.tlsConfig.RootCAs = certPool
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
func (c *Client) ConnectWithOptions(hostname, ip, port string, options clients.ConnectOptions) (*clients.Response, error) {
	// Get ztls config using input
	config, err := c.getConfig(hostname, ip, port, options)
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("failed to create ztls config")
	}

	ctx := context.Background()
	if c.options.Timeout != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(c.options.Timeout)*time.Second)
		defer cancel()
	}

	// setup tcp connection
	conn, err := clients.GetConn(ctx, hostname, ip, port, c.options)
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("failed to setup connection").WithTag("ztls")
	}
	defer conn.Close() //internally done by conn.Close() so just a placeholder

	// get resolvedIp
	resolvedIP, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return nil, err
	}

	// new tls connection
	tlsConn := tls.Client(conn, config)
	if err := c.tlsHandshakeWithTimeout(tlsConn, ctx); err != nil {
		return nil, errorutil.NewWithTag("ztls", "could not do tls handshake").Wrap(err)
	}
	defer tlsConn.Close()

	hl := tlsConn.GetHandshakeLog()

	now := time.Now()
	response := &clients.Response{
		Timestamp:     &now,
		Host:          hostname,
		IP:            resolvedIP,
		ProbeStatus:   true,
		Port:          port,
		TLSConnection: "ztls",
		ServerName:    config.ServerName,
	}
	if hl != nil && hl.ServerCertificates != nil {
		response.CertificateResponse = ConvertCertificateToResponse(c.options, hostname, ParseSimpleTLSCertificate(hl.ServerCertificates.Certificate))
		if response.CertificateResponse != nil {
			response.Untrusted = clients.IsZTLSUntrustedCA(hl.ServerCertificates.Chain)
		}
	}
	if hl.ServerHello != nil {
		response.Version = versionToTLSVersionString[uint16(hl.ServerHello.Version)]
		response.Cipher = hl.ServerHello.CipherSuite.String()

	}

	if c.options.TLSChain {
		for _, cert := range hl.ServerCertificates.Chain {
			response.Chain = append(response.Chain, ConvertCertificateToResponse(c.options, hostname, ParseSimpleTLSCertificate(cert)))
		}
	}
	if c.options.Ja3 {
		response.Ja3Hash = ja3.GetJa3Hash(hl.ClientHello)
	}
	if c.options.ClientHello {
		response.ClientHello = hl.ClientHello
	}
	if c.options.ServerHello {
		response.ServerHello = hl.ServerHello
	}
	return response, nil
}

// EnumerateCiphers enumerate target with ciphers supported by ztls
func (c *Client) EnumerateCiphers(hostname, ip, port string, options clients.ConnectOptions) ([]string, error) {
	// filter ciphers based on given seclevel
	toEnumerate := clients.GetCiphersWithLevel(AllCiphersNames, options.CipherLevel...)

	enumeratedCiphers := []string{}

	// get network address
	var address string
	if iputil.IsIP(ip) && (c.options.ScanAllIPs || len(c.options.IPVersion) > 0) {
		address = net.JoinHostPort(ip, port)
	} else {
		address = net.JoinHostPort(hostname, port)
	}

	threads := c.options.CipherConcurrency
	if len(toEnumerate) < threads {
		threads = len(toEnumerate)
	}

	// setup connection pool
	pool, err := connpool.NewOneTimePool(context.Background(), address, threads)
	if err != nil {
		return enumeratedCiphers, errorutil.NewWithErr(err).Msgf("failed to setup connection pool")
	}
	pool.Dialer = c.dialer
	go func() {
		if err := pool.Run(); err != nil && !errors.Is(err, context.Canceled) {
			gologger.Error().Msgf("tlsx: ztls: failed to run connection pool: %v", err)
		}
	}()
	defer pool.Close()

	// create ztls base config
	baseCfg, err := c.getConfig(hostname, ip, port, options)
	if err != nil {
		return enumeratedCiphers, errorutil.NewWithErr(err).Msgf("failed to setup cfg")
	}
	gologger.Debug().Label("ztls").Msgf("Starting cipher enumeration with %v ciphers in %v", len(toEnumerate), options.VersionTLS)

	for _, v := range toEnumerate {
		baseConn, err := pool.Acquire(context.Background())
		if err != nil {
			return enumeratedCiphers, errorutil.NewWithErr(err).WithTag("ztls")
		}
		stats.IncrementZcryptoTLSConnections()
		conn := tls.Client(baseConn, baseCfg)
		baseCfg.CipherSuites = []uint16{ztlsCiphers[v]}

		if err := c.tlsHandshakeWithTimeout(conn, context.TODO()); err == nil {
			h1 := conn.GetHandshakeLog()
			enumeratedCiphers = append(enumeratedCiphers, h1.ServerHello.CipherSuite.String())
		}
		_ = conn.Close() // also closes baseConn internally
	}
	return enumeratedCiphers, nil
}

// SupportedTLSVersions returns the list of ztls library supported tls versions
func (c *Client) SupportedTLSVersions() ([]string, error) {
	return SupportedTlsVersions, nil
}

// SupportedTLSCiphers returns the list of ztls library supported ciphers
func (c *Client) SupportedTLSCiphers() ([]string, error) {
	return AllCiphersNames, nil
}

// getConfig returns tlsconfig for ztls
func (c *Client) getConfig(hostname, ip, port string, options clients.ConnectOptions) (*tls.Config, error) {
	// In enum mode return if given options are not supported
	if options.EnumMode == clients.Version && (options.VersionTLS == "" || !stringsutil.EqualFoldAny(options.VersionTLS, SupportedTlsVersions...)) {
		// version not supported
		return nil, errorutil.NewWithTag("ztls", "tlsversion `%v` not supported in ztls", options.VersionTLS)
	}
	if options.EnumMode == clients.Cipher && !stringsutil.EqualFoldAny(options.VersionTLS, SupportedTlsVersions...) {
		return nil, errorutil.NewWithTag("ztls", "cipher enum with version %v not implemented", options.VersionTLS)
	}

	config := c.tlsConfig
	if config.ServerName == "" {
		cfg := config.Clone()
		if options.SNI != "" {
			cfg.ServerName = options.SNI
		} else if iputil.IsIP(hostname) && c.options.RandomForEmptyServerName {
			// using a random sni will return the default server certificate
			cfg.ServerName = xid.New().String()
		} else {
			cfg.ServerName = hostname
		}
		config = cfg
	}

	if options.VersionTLS != "" {
		version, ok := versionStringToTLSVersion[options.VersionTLS]
		if !ok {
			return nil, errorutil.NewWithTag("ztls", "invalid tls version specified: %s", options.VersionTLS)
		}
		config.MinVersion = version
		config.MaxVersion = version
	}

	if len(options.Ciphers) > 0 && options.EnumMode != clients.Cipher {
		customCiphers, err := toZTLSCiphers(options.Ciphers)
		if err != nil {
			return nil, errorutil.NewWithTag("ztls", "could not get tls ciphers").Wrap(err)
		}
		c.tlsConfig.CipherSuites = customCiphers
	}
	return config, nil
}

// tlsHandshakeWithCtx attempts tls handshake with given timeout
func (c *Client) tlsHandshakeWithTimeout(tlsConn *tls.Conn, ctx context.Context) error {
	errChan := make(chan error, 1)
	defer close(errChan)

	select {
	case <-ctx.Done():
		return errorutil.NewWithTag("ztls", "timeout while attempting handshake")
	case errChan <- tlsConn.Handshake():
	}

	err := <-errChan
	if err == tls.ErrCertsOnly {
		err = nil
	}
	return err
}
