//go:build !openssl

// Package openssl implements a tls grabbing implementation using openssl
package openssl

import (
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
)

// Enabled reports if the tool was compiled with openssl support
const Enabled = false

// Client is a TLS grabbing client using crypto/tls
type Client struct{}

// New creates a new grabbing client using crypto/tls
func New(options *clients.Options) (*Client, error) {
	return nil, ErrNotSupported
}

// Connect connects to a host and grabs the response data
func (c *Client) ConnectWithOptions(hostname, ip, port string, options clients.ConnectOptions) (*clients.Response, error) {
	return nil, ErrNotSupported
}
