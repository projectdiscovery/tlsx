// Package auto implements an automatic fallback mechanism based tls
// client which uses both crypto/tls first and zcrypto/tls on tls errors.
package auto

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/tlsx/pkg/output/stats"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/tls"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/ztls"
)

// Client is a TLS grabbing client using auto fallback
type Client struct {
	tlsClient  *tls.Client
	ztlsClient *ztls.Client
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
	return &Client{tlsClient: tlsClient, ztlsClient: ztlsClient}, nil
}

// Connect connects to a host and grabs the response data
func (c *Client) ConnectWithOptions(hostname, ip, port string, options clients.ConnectOptions) (*clients.Response, error) {
	response, err := c.tlsClient.ConnectWithOptions(hostname, ip, port, options)
	isInvalidResponse := c.isResponseInvalid(response)
	if err != nil || isInvalidResponse {
		ztlsResponse, ztlsErr := c.ztlsClient.ConnectWithOptions(hostname, ip, port, options)
		if ztlsErr != nil {
			return nil, ztlsErr
		}
		ztlsResponse.TLSConnection = "ztls"
		stats.IncrementZcryptoTLSConnections()
		return ztlsResponse, nil
	}
	response.TLSConnection = "ctls"
	stats.IncrementCryptoTLSConnections()
	return response, nil
}

// isResponseInvalid handles invalid response
func (c *Client) isResponseInvalid(resp *clients.Response) bool {
	if resp == nil {
		return true
	}
	// case for invalid google resolving response
	if strings.EqualFold(resp.CertificateResponse.IssuerCN, "invalid2.invalid") {
		return true
	}
	return false
}
