package ztls_test

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	ctls "crypto/tls"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/ztls"
)

func TestClientCertRequired(t *testing.T) {
	cases := []struct {
		name             string
		clientAuthConfig ctls.ClientAuthType
		tlsVersion       string
		expectedResult   *bool
	}{
		{
			name:             "tls10_cert_required_by_server",
			clientAuthConfig: ctls.RequireAnyClientCert,
			tlsVersion:       "tls10",
			expectedResult:   boolPtr(true),
		},
		{
			name:             "tls11_cert_required_by_server",
			clientAuthConfig: ctls.RequireAnyClientCert,
			tlsVersion:       "tls11",
			expectedResult:   boolPtr(true),
		},
		{
			name:             "tls12_cert_required_by_server",
			clientAuthConfig: ctls.RequireAnyClientCert,
			tlsVersion:       "tls12",
			expectedResult:   boolPtr(true),
		},
		{
			name:             "tls12_cert_not_required_by_server",
			clientAuthConfig: ctls.NoClientCert,
			tlsVersion:       "tls12",
			expectedResult:   boolPtr(false),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			log.SetOutput(io.Discard) // discard logs

			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = fmt.Fprintf(w, "OK")
			}))

			server.TLS.ClientAuth = tc.clientAuthConfig
			server.TLS.MinVersion = ctls.VersionTLS10
			defer server.Close()

			parsedUrl, err := url.Parse(server.URL)
			if err != nil {
				t.Errorf("error parsing test server url: %s", err)
			}

			connectOpts := clients.ConnectOptions{
				VersionTLS: tc.tlsVersion,
			}

			dialer, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
			if err != nil {
				t.Errorf("error initializing dialer: %s", err)
			}

			clientOpts := &clients.Options{
				Fastdialer: dialer,
			}

			client, err := ztls.New(clientOpts)
			if err != nil {
				t.Errorf("error initializing ztls client: %s", err)
			}

			host := parsedUrl.Hostname()
			resp, err := client.ConnectWithOptions(host, host, parsedUrl.Port(), connectOpts)
			if err != nil {
				t.Errorf("client ConnectWithOptions call failed: %s", err)
			}

			actualResult := resp.ClientCertRequired

			if tc.expectedResult != nil && actualResult == nil {
				t.Errorf("expected isClientCertRequired = %t but received nil", *tc.expectedResult)
			} else if tc.expectedResult == nil && actualResult != nil {
				t.Errorf("expected isClientCertRequired = nil but received %t", *actualResult)
			} else if *tc.expectedResult != *actualResult {
				t.Errorf("expected isClientCertRequired = %t but received %t", *tc.expectedResult, *actualResult)
			}
		})
	}
}

func boolPtr(v bool) *bool {
	return &v
}

// TestHandshakeTimeout verifies that tlsx does not hang indefinitely
// when connecting to a host that accepts TCP but never completes TLS.
// Regression test for https://github.com/projectdiscovery/tlsx/issues/819
func TestHandshakeTimeout(t *testing.T) {
	// Start a TCP listener that accepts connections but never speaks TLS
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Hold the connection open but never send any data
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	addr := ln.Addr().String()
	host, port, _ := net.SplitHostPort(addr)

	dialerOpts := fastdialer.DefaultOptions
	dialerOpts.EnableFallback = false
	fd, err := fastdialer.NewDialer(dialerOpts)
	if err != nil {
		t.Fatal(err)
	}

	client, err := ztls.New(&clients.Options{
		Timeout: 3, // 3 second timeout
		Fastdialer: fd,
	})
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = client.ConnectWithOptions(host, host, port, clients.ConnectOptions{})
	}()

	select {
	case <-done:
		// Success: the connection returned (with error) within timeout
	case <-time.After(10 * time.Second):
		t.Fatal("tlsx hung indefinitely — handshake timeout not working")
	}
}
