// Package auto implements an automatic fallback mechanism based tls
// client which uses both crypto/tls first and zcrypto/tls on tls errors.
package auto

import (
	"sync"

	"github.com/projectdiscovery/tlsx/pkg/output/stats"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/openssl"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/tls"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/ztls"
	errorutils "github.com/projectdiscovery/utils/errors"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"go.uber.org/multierr"
)

// Client is a TLS grabbing client using auto fallback
type Client struct {
	tlsClient     *tls.Client
	ztlsClient    *ztls.Client
	opensslClient *openssl.Client
	options       *clients.Options
}

// New creates a new grabbing client using auto fallback
func New(options *clients.Options) (*Client, error) {
	tlsClient, tlsErr := tls.New(options)
	ztlsClient, ztlsErr := ztls.New(options)
	opensslClient, opensslErr := openssl.New(options)

	if tlsErr != nil && ztlsErr != nil && (opensslErr != nil && !errorutils.IsAny(opensslErr, openssl.ErrNotAvailable)) {
		return nil, multierr.Combine(tlsErr, ztlsErr, opensslErr)
	}
	return &Client{tlsClient: tlsClient, ztlsClient: ztlsClient, opensslClient: opensslClient, options: options}, nil
}

// Connect connects to a host and grabs the response data
func (c *Client) ConnectWithOptions(hostname, ip, port string, options clients.ConnectOptions) (*clients.Response, error) {
	var response *clients.Response
	var err, ztlsErr, opensslErr error
	maxRetries := c.options.Retries
	if maxRetries < 3 {
		maxRetries = 3
	}
	retryCounter := 0
	if c.tlsClient == nil && c.ztlsClient == nil && c.opensslClient == nil {
		// logic to avoid infinite loop
		return nil, errorutils.New("no tls client available available for auto mode")
	}
	var errStack error
	for retryCounter < maxRetries {
		if c.tlsClient != nil {
			if response, err = c.tlsClient.ConnectWithOptions(hostname, ip, port, options); err == nil {
				response.TLSConnection = "ctls"
				stats.IncrementCryptoTLSConnections()
				return response, nil
			}
			retryCounter++
		}
		if c.ztlsClient != nil {
			if response, ztlsErr = c.ztlsClient.ConnectWithOptions(hostname, ip, port, options); ztlsErr == nil {
				response.TLSConnection = "ztls"
				stats.IncrementZcryptoTLSConnections()
				return response, nil
			}
			retryCounter++
		}
		if c.opensslClient != nil {
			if response, opensslErr = c.opensslClient.ConnectWithOptions(hostname, ip, port, options); opensslErr == nil {
				response.TLSConnection = "openssl"
				stats.IncrementOpensslTLSConnections()
				return response, nil
			}
			if errorutils.IsAny(opensslErr, openssl.ErrNotAvailable) {
				opensslErr = nil
			}
			retryCounter++
		}
		errStack = multierr.Combine(errStack, err, ztlsErr, opensslErr)
	}
	return nil, errStack
}

func (c *Client) EnumerateCiphers(hostname, ip, port string, options clients.ConnectOptions) ([]string, error) {
	wg := &sync.WaitGroup{}
	ciphersFound := []string{}
	cipherMutex := &sync.Mutex{}
	allClients := []clients.Implementation{}
	if c.opensslClient != nil {
		allClients = append(allClients, c.opensslClient)
	}
	if c.ztlsClient != nil {
		allClients = append(allClients, c.ztlsClient)
	}
	if c.tlsClient != nil {
		allClients = append(allClients, c.tlsClient)
	}

	for _, v := range allClients {
		wg.Add(1)
		go func(clientx clients.Implementation) {
			defer wg.Done()
			if res, _ := clientx.EnumerateCiphers(hostname, ip, port, options); len(res) > 0 {
				cipherMutex.Lock()
				ciphersFound = append(ciphersFound, res...)
				cipherMutex.Unlock()
			}
		}(v)
	}
	wg.Wait()
	//Dedupe and return
	return sliceutil.Dedupe(ciphersFound), nil
}

// SupportedTLSVersions returns the list of supported tls versions by all engines
func (c *Client) SupportedTLSVersions() ([]string, error) {
	return supportedTlsVersions, nil
}

// SupportedTLSCiphers returns the list of supported ciphers by all engines
func (c *Client) SupportedTLSCiphers() ([]string, error) {
	return allCiphersNames, nil
}
