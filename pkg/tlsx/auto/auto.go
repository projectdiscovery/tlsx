// Package auto implements an automatic fallback mechanism based tls
// client which uses both crypto/tls first and zcrypto/tls on tls errors.
package auto

import (
	"github.com/pkg/errors"
	"github.com/projectdiscovery/tlsx/pkg/output/stats"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/openssl"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/tls"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/ztls"
)

// Client is a TLS grabbing client using auto fallback
type Client struct {
	tlsClient     *tls.Client
	ztlsClient    *ztls.Client
	opensslClient *openssl.Client
}

// New creates a new grabbing client using auto fallback
func New(options *clients.Options) (*Client, error) {
	tlsClient, err := tls.New(options)
	if err != nil {
		return nil, errors.Wrap(err, "could not create tls client")
	}
	ztlsClient, err := ztls.New(options)
	if err != nil {
		return nil, errors.Wrap(err, "could not create ztls client")
	}
	opensslClient, err := openssl.New(options)
	if err != nil && err != openssl.ErrNotSupported {
		return nil, errors.Wrap(err, "could not create ztls client")
	}
	return &Client{tlsClient: tlsClient, ztlsClient: ztlsClient, opensslClient: opensslClient}, nil
}

// Connect connects to a host and grabs the response data
func (c *Client) ConnectWithOptions(hostname, ip, port string, options clients.ConnectOptions) (*clients.Response, error) {
	response, err := c.tlsClient.ConnectWithOptions(hostname, ip, port, options)
	if err != nil {
		ztlsResponse, ztlsErr := c.ztlsClient.ConnectWithOptions(hostname, ip, port, options)
		if ztlsErr != nil {
			opensslResponse, opensslError := c.opensslClient.ConnectWithOptions(hostname, ip, port, options)
			if opensslError != nil {
				return nil, opensslError
			}
			opensslResponse.TLSConnection = "openssl"
			stats.IncrementOpensslTLSConnections()
			return opensslResponse, nil
		}
		ztlsResponse.TLSConnection = "ztls"
		stats.IncrementZcryptoTLSConnections()
		return ztlsResponse, nil
	}
	response.TLSConnection = "ctls"
	stats.IncrementCryptoTLSConnections()
	return response, nil
}

// SupportedTLSVersions is meaningless here but necessary due to the interface system implemented
func (c *Client) SupportedTLSVersions() ([]string, error) {
	return nil, errors.New("not implemented in auto mode")
}

// SupportedTLSVersions is meaningless here but necessary due to the interface system implemented
func (c *Client) SupportedTLSCiphers() ([]string, error) {
	return nil, errors.New("not implemented in auto mode")
}
