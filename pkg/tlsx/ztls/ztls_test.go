package ztls_test

import (
	"context"
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

// TestHandshakeTimeout verifies that ConnectWithOptions respects the timeout
// when a server never completes the TLS handshake. Before the fix,
// tlsHandshakeWithTimeout evaluated Handshake() synchronously inside the
// select case expression, making the timeout unreachable.
func TestHandshakeTimeout(t *testing.T) {
	// Start a TCP server that accepts connections but never sends any data,
	// simulating a host that hangs during the TLS handshake.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// deliberately never respond — simulates a hung handshake
			defer conn.Close()
		}
	}()

	addr := ln.Addr().String()
	host, port, _ := net.SplitHostPort(addr)

	dialer, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
	if err != nil {
		t.Fatalf("error initializing dialer: %v", err)
	}

	timeoutSecs := 2
	clientOpts := &clients.Options{
		Fastdialer: dialer,
		Timeout:    timeoutSecs,
	}

	client, err := ztls.New(clientOpts)
	if err != nil {
		t.Fatalf("error initializing ztls client: %v", err)
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSecs+2)*time.Second)
	defer cancel()
	_ = ctx // ConnectWithOptions uses client.options.Timeout internally

	_, _ = client.ConnectWithOptions(host, host, port, clients.ConnectOptions{})
	elapsed := time.Since(start)

	// The call must return within roughly timeout + 1s grace period.
	// Before the fix it would block indefinitely.
	maxAllowed := time.Duration(timeoutSecs+1) * time.Second
	if elapsed > maxAllowed {
		t.Errorf("ConnectWithOptions hung: took %v, expected < %v", elapsed, maxAllowed)
	}
	t.Logf("ConnectWithOptions returned in %v (timeout=%ds) — OK", elapsed.Round(time.Millisecond), timeoutSecs)
}
