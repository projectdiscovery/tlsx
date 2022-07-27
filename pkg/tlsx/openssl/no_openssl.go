//go:build !openssl

// Package openssl implements a tls grabbing implementation using openssl
package openssl

import (
	"github.com/pkg/errors"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
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
	return nil, errors.New("openssl not supported")
}

// Connect connects to a host and grabs the response data
func (c *Client) ConnectWithOptions(hostname, ip, port string, options clients.ConnectOptions) (*clients.Response, error) {
	return nil, errors.New("not supported")
}
