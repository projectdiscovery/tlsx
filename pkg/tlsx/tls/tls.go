// Package tls implements a tls grabbing implementation using
// standard package crypto/tls library.
package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/tlsx/pkg/output/stats"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/projectdiscovery/utils/conn/connpool"
	errorutil "github.com/projectdiscovery/utils/errors"
	iputil "github.com/projectdiscovery/utils/ip"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/rs/xid"
)

// Client is a TLS grabbing client using crypto/tls
type Client struct {
	dialer    *fastdialer.Dialer
	tlsConfig *tls.Config
	options   *clients.Options
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
		dialer: options.Fastdialer,
		tlsConfig: &tls.Config{
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
			InsecureSkipVerify: !options.VerifyServerCertificate,
		},
		options: options,
	}

	if len(options.Ciphers) > 0 {
		if customCiphers, err := toTLSCiphers(options.Ciphers); err != nil {
			return nil, errorutil.NewWithTag("ctls", "could not get tls ciphers").Wrap(err)
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
			return nil, errorutil.NewWithTag("ctls", "could not read ca certificate").Wrap(err)
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
			return nil, errorutil.NewWithTag("ctls", "invalid min version specified: %s", options.MinVersion)
		} else {
			c.tlsConfig.MinVersion = version
		}
	}
	if options.MaxVersion != "" {
		version, ok := versionStringToTLSVersion[options.MaxVersion]
		if !ok {
			return nil, errorutil.NewWithTag("ctls", "invalid max version specified: %s", options.MaxVersion)
		} else {
			c.tlsConfig.MaxVersion = version
		}
	}
	return c, nil
}

// Connect connects to a host and grabs the response data
func (c *Client) ConnectWithOptions(hostname, ip, port string, options clients.ConnectOptions) (*clients.Response, error) {
	// Get Config based on options
	config, err := c.getConfig(hostname, ip, port, options)
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("failed to connect got cfg error")
	}

	ctx := context.Background()
	if c.options.Timeout != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(c.options.Timeout)*time.Second)
		defer cancel()
	}

	// setup a net conn
	rawConn, err := clients.GetConn(ctx, hostname, ip, port, c.options)
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("failed to setup connection").WithTag("ctls")
	}
	// defer rawConn.Close() //internally done by conn.Close() so just a placeholder

	conn := tls.Client(rawConn, config)
	if err := conn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, errorutil.NewWithTag("ctls", "could not do handshake").Wrap(err)
	}
	defer conn.Close()

	connectionState := conn.ConnectionState()
	if len(connectionState.PeerCertificates) == 0 {
		return nil, errorutil.New("no certificates returned by server")
	}
	tlsVersion := versionToTLSVersionString[connectionState.Version]
	tlsCipher := tls.CipherSuiteName(connectionState.CipherSuite)

	leafCertificate := connectionState.PeerCertificates[0]
	certificateChain := connectionState.PeerCertificates[1:]

	resolvedIP, _, err := net.SplitHostPort(rawConn.RemoteAddr().String())
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
		Version:             tlsVersion,
		Cipher:              tlsCipher,
		TLSConnection:       "ctls",
		CertificateResponse: clients.Convertx509toResponse(c.options, hostname, leafCertificate, c.options.Cert),
		ServerName:          config.ServerName,
	}
	response.Untrusted = clients.IsUntrustedCA(certificateChain)
	if c.options.TLSChain {
		for _, cert := range certificateChain {
			response.Chain = append(response.Chain, clients.Convertx509toResponse(c.options, hostname, cert, c.options.Cert))
		}
	}
	return response, nil
}

func (c *Client) EnumerateCiphers(hostname, ip, port string, options clients.ConnectOptions) ([]string, error) {
	// filter ciphers based on given seclevel
	toEnumerate := clients.GetCiphersWithLevel(AllCiphersNames, options.CipherLevel...)

	if options.VersionTLS == "tls13" {
		return nil, errorutil.NewWithTag("ctls", "cipher enum not supported in ctls with tls1.3")
	}

	enumeratedCiphers := []string{}

	baseCfg, err := c.getConfig(hostname, ip, port, options)
	if err != nil {
		return enumeratedCiphers, errorutil.NewWithErr(err).Msgf("failed to setup cfg")
	}
	gologger.Debug().Label("ctls").Msgf("Starting cipher enumeration with %v ciphers and version %v", len(toEnumerate), options.VersionTLS)

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
			gologger.Error().Msgf("tlsx: ctls: failed to run connection pool: %v", err)
		}
	}()
	defer pool.Close()

	for _, v := range toEnumerate {
		// create new baseConn and pass it to tlsclient
		baseConn, err := pool.Acquire(context.Background())
		if err != nil {
			return enumeratedCiphers, errorutil.NewWithErr(err).WithTag("ctls")
		}
		stats.IncrementCryptoTLSConnections()
		baseCfg.CipherSuites = []uint16{tlsCiphers[v]}

		conn := tls.Client(baseConn, baseCfg)

		if err := conn.Handshake(); err == nil {
			ciphersuite := conn.ConnectionState().CipherSuite
			enumeratedCiphers = append(enumeratedCiphers, tls.CipherSuiteName(ciphersuite))
		}
		_ = conn.Close() // close baseConn internally
	}
	return enumeratedCiphers, nil
}

// SupportedTLSVersions returns the list of standard tls library supported tls versions
func (c *Client) SupportedTLSVersions() ([]string, error) {
	return SupportedTlsVersions, nil
}

// SupportedTLSCiphers returns the list of standard tls library supported ciphers
func (c *Client) SupportedTLSCiphers() ([]string, error) {
	return AllCiphersNames, nil
}

// getConfig returns a valid config to be used by client
func (c *Client) getConfig(hostname, ip, port string, options clients.ConnectOptions) (*tls.Config, error) {
	// In enum mode return if given options are not supported
	if options.EnumMode == clients.Version && (options.VersionTLS == "" || !stringsutil.EqualFoldAny(options.VersionTLS, SupportedTlsVersions...)) {
		// version not supported
		return nil, errorutil.NewWithTag("ctls", "tlsversion `%v` not supported in ctls", options.VersionTLS)
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
			return nil, errorutil.New("invalid tls version specified: %s", options.VersionTLS).WithTag("ctls")
		}
		config.MinVersion = version
		config.MaxVersion = version
	}

	if len(options.Ciphers) > 0 && options.EnumMode != clients.Cipher {
		customCiphers, err := toTLSCiphers(options.Ciphers)
		if err != nil {
			return nil, errorutil.NewWithTag("ctls", "could not get tls ciphers").Wrap(err)
		}
		c.tlsConfig.CipherSuites = customCiphers
	}
	if options.EnumMode == clients.Cipher && !stringsutil.EqualFoldAny(options.VersionTLS, SupportedTlsVersions...) {
		return nil, errorutil.NewWithTag("ctls", "cipher enum with version %v not implemented", options.VersionTLS)
	}
	return config, nil
}
