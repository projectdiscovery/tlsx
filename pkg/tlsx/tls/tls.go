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
	"sort"
	"sync"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/tlsx/pkg/output/stats"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/projectdiscovery/utils/conn/connpool"
	errorutil "github.com/projectdiscovery/utils/errors" //nolint
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
			return nil, errorutil.NewWithTag("ctls", "could not get tls ciphers").Wrap(err) //nolint
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
			return nil, errorutil.NewWithTag("ctls", "could not read ca certificate").Wrap(err) //nolint
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
			return nil, errorutil.NewWithTag("ctls", "invalid min version specified: %s", options.MinVersion) //nolint
		} else {
			c.tlsConfig.MinVersion = version
		}
	}
	if options.MaxVersion != "" {
		version, ok := versionStringToTLSVersion[options.MaxVersion]
		if !ok {
			return nil, errorutil.NewWithTag("ctls", "invalid max version specified: %s", options.MaxVersion) //nolint
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
		return nil, errorutil.NewWithErr(err).Msgf("failed to connect got cfg error") //nolint
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
		return nil, errorutil.NewWithErr(err).Msgf("failed to setup connection").WithTag("ctls") //nolint
	}

	var clientCertRequired bool
	conn := tls.Client(rawConn, config)

	// Some TLS servers accept the TCP connection but never
	// respond to the ClientHello. Without an explicit timeout
	// at the handshake level, the process can block indefinitely,
	// eventually stalling large-scale scans.
	errChan := make(chan error, 1)
	go func() {
		errChan <- conn.HandshakeContext(ctx)
	}()

	select {
	case <-ctx.Done():
		// Closing the raw connection is safer as TLS layers might hold internal locks.
		_ = rawConn.Close()
		// Synchronously drain the channel to ensure the goroutine exits before returning.
		<-errChan
		return nil, errorutil.NewWithTag("ctls", "timeout while attempting handshake").Wrap(ctx.Err()) //nolint
	case err = <-errChan:
		if err != nil {
			if clients.IsClientCertRequiredError(err) {
				clientCertRequired = true
			} else {
				_ = rawConn.Close()
				return nil, errorutil.NewWithTag("ctls", "could not do handshake").Wrap(err) //nolint
			}
		}
	}

	defer func() {
		_ = conn.Close()
	}()

	connectionState := conn.ConnectionState()
	if len(connectionState.PeerCertificates) == 0 {
		return nil, errorutil.New("no certificates returned by server") //nolint
	}
	tlsVersion := versionToTLSVersionString[connectionState.Version]
	tlsCipher := tls.CipherSuiteName(connectionState.CipherSuite)

	// Read the negotiated key exchange group (available from Go 1.25+).
	// In TLS 1.3 the cipher suite name no longer encodes the key agreement
	// mechanism (e.g. both X25519 and X25519MLKEM768 report the same
	// TLS_AES_128_GCM_SHA256 suite), so CurveID is the only way to distinguish
	// classical from post-quantum key exchange.
	keyExchange := ""
	if connectionState.CurveID != 0 {
		keyExchange = connectionState.CurveID.String()
	}

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
		KeyExchange:         keyExchange,
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

	if response.Version != "tls13" {
		response.ClientCertRequired = &clientCertRequired
	}
	return response, nil
}

func (c *Client) EnumerateCiphers(hostname, ip, port string, options clients.ConnectOptions) ([]string, error) {
	// filter ciphers based on given seclevel
	toEnumerate := clients.GetCiphersWithLevel(AllCiphersNames, options.CipherLevel...)

	if options.VersionTLS == "tls13" {
		return nil, errorutil.NewWithTag("ctls", "cipher enum not supported in ctls with tls1.3") //nolint
	}

	enumeratedCiphers := []string{}

	baseCfg, err := c.getConfig(hostname, ip, port, options)
	if err != nil {
		return enumeratedCiphers, errorutil.NewWithErr(err).Msgf("failed to setup cfg") //nolint
	}
	gologger.Debug().Label("ctls").Msgf("Starting cipher enumeration with %v ciphers and version %v", len(toEnumerate), options.VersionTLS)

	// get network address
	var address string
	if iputil.IsIP(ip) && (c.options.ScanAllIPs || len(c.options.IPVersion) > 0) {
		address = net.JoinHostPort(ip, port)
	} else {
		address = net.JoinHostPort(hostname, port)
	}

	if len(toEnumerate) == 0 {
		return enumeratedCiphers, nil
	}

	// Internal validation to prevent deadlocks if options are not clamped elsewhere.
	if c.options.Timeout <= 0 {
		c.options.Timeout = 5
	}
	if c.options.CipherConcurrency <= 0 {
		c.options.CipherConcurrency = 1
	}

	threads := c.options.CipherConcurrency
	if len(toEnumerate) < threads {
		threads = len(toEnumerate)
	}

	// setup connection pool
	pool, err := connpool.NewOneTimePool(context.Background(), address, threads)
	if err != nil {
		return enumeratedCiphers, errorutil.NewWithErr(err).Msgf("failed to setup connection pool") //nolint
	}
	pool.Dialer = c.dialer
	go func() {
		if err := pool.Run(); err != nil && !errors.Is(err, context.Canceled) {
			gologger.Error().Msgf("tlsx: ctls: failed to run connection pool: %v", err)
		}
	}()
	defer func() {
		_ = pool.Close()
	}()

	// enumerate ciphers concurrently bounded by CipherConcurrency; the pool keeps
	// dialing fresh connections so each worker can acquire one independently.
	var (
		mu        sync.Mutex
		wg        sync.WaitGroup
		ciphersCh = make(chan string)
	)
	enumerate := func(v string) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.options.Timeout)*time.Second)
		defer cancel()

		baseConn, err := pool.Acquire(ctx)
		if err != nil || baseConn == nil {
			return
		}
		defer baseConn.Close() //nolint:errcheck

		stats.IncrementCryptoTLSConnections()

		cfg := baseCfg.Clone()
		cfg.CipherSuites = []uint16{tlsCiphers[v]}
		conn := tls.Client(baseConn, cfg)
		defer conn.Close() //nolint:errcheck

		errChan := make(chan error, 1)
		go func() {
			errChan <- conn.HandshakeContext(ctx)
		}()

		select {
		case <-ctx.Done():
			_ = baseConn.Close()
			<-errChan
		case err := <-errChan:
			if err == nil {
				ciphersuite := conn.ConnectionState().CipherSuite
				mu.Lock()
				enumeratedCiphers = append(enumeratedCiphers, tls.CipherSuiteName(ciphersuite))
				mu.Unlock()
			}
		}
	}

	wg.Add(threads)
	for i := 0; i < threads; i++ {
		go func() {
			defer wg.Done()
			for v := range ciphersCh {
				enumerate(v)
			}
		}()
	}
	for _, v := range toEnumerate {
		ciphersCh <- v
	}
	close(ciphersCh)
	wg.Wait()

	sort.Strings(enumeratedCiphers)
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
		return nil, errorutil.NewWithTag("ctls", "tlsversion `%v` not supported in ctls", options.VersionTLS) //nolint
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
			return nil, errorutil.New("invalid tls version specified: %s", options.VersionTLS).WithTag("ctls") //nolint
		}
		config.MinVersion = version
		config.MaxVersion = version
	}

	if len(options.Ciphers) > 0 && options.EnumMode != clients.Cipher {
		customCiphers, err := toTLSCiphers(options.Ciphers)
		if err != nil {
			return nil, errorutil.NewWithTag("ctls", "could not get tls ciphers").Wrap(err) //nolint
		}
		c.tlsConfig.CipherSuites = customCiphers
	}
	if options.EnumMode == clients.Cipher && !stringsutil.EqualFoldAny(options.VersionTLS, SupportedTlsVersions...) {
		return nil, errorutil.NewWithTag("ctls", "cipher enum with version %v not implemented", options.VersionTLS) //nolint
	}
	return config, nil
}
