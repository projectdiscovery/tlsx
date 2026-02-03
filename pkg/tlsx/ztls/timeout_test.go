package ztls_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/ztls"
)

// TestHandshakeTimeout verifies that TLS handshakes properly timeout
// instead of hanging indefinitely when the server is unresponsive.
func TestHandshakeTimeout(t *testing.T) {
	log.SetOutput(io.Discard)

	// Create a listener that accepts connections but never completes TLS handshake
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	// Accept connections but don't respond (simulates unresponsive server)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Hold connection open but never respond - simulates hanging server
			go func(c net.Conn) {
				defer c.Close()
				// Wait for connection to be closed by client timeout
				time.Sleep(30 * time.Second)
			}(conn)
		}
	}()

	addr := listener.Addr().String()
	host, port, _ := net.SplitHostPort(addr)

	dialer, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
	if err != nil {
		t.Fatalf("failed to create dialer: %v", err)
	}

	clientOpts := &clients.Options{
		Fastdialer: dialer,
		Timeout:    2, // 2 second timeout
	}

	client, err := ztls.New(clientOpts)
	if err != nil {
		t.Fatalf("failed to create ztls client: %v", err)
	}

	connectOpts := clients.ConnectOptions{
		VersionTLS: "tls12",
	}

	start := time.Now()
	_, err = client.ConnectWithOptions(host, host, port, connectOpts)
	elapsed := time.Since(start)

	// Connection should fail (timeout or connection error)
	if err == nil {
		t.Error("expected error from unresponsive server, got nil")
	}

	// Should complete within reasonable time (timeout + small buffer)
	if elapsed > 10*time.Second {
		t.Errorf("handshake took too long (%v), timeout may not be working", elapsed)
	}

	t.Logf("handshake correctly timed out after %v with error: %v", elapsed, err)
}

// TestCipherEnumerationTimeout verifies cipher enumeration uses timeouts
func TestCipherEnumerationTimeout(t *testing.T) {
	log.SetOutput(io.Discard)

	// Create a proper TLS server for cipher enumeration
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "OK")
	}))
	server.TLS.MinVersion = tls.VersionTLS10
	defer server.Close()

	parsedUrl, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}

	dialer, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
	if err != nil {
		t.Fatalf("failed to create dialer: %v", err)
	}

	clientOpts := &clients.Options{
		Fastdialer:        dialer,
		Timeout:           5,
		CipherConcurrency: 3,
	}

	client, err := ztls.New(clientOpts)
	if err != nil {
		t.Fatalf("failed to create ztls client: %v", err)
	}

	connectOpts := clients.ConnectOptions{
		VersionTLS:  "tls12",
		EnumMode:    clients.Cipher,
		CipherLevel: []clients.CipherSecLevel{clients.Secure},
	}

	host := parsedUrl.Hostname()

	// Create a context with timeout for the entire enumeration
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan struct{})
	var ciphers []string
	var enumErr error

	go func() {
		ciphers, enumErr = client.EnumerateCiphers(host, host, parsedUrl.Port(), connectOpts)
		close(done)
	}()

	select {
	case <-ctx.Done():
		t.Fatal("cipher enumeration hung - timeout not working")
	case <-done:
		// Enumeration completed (may have errors, but didn't hang)
		if enumErr != nil {
			t.Logf("cipher enumeration completed with error (expected for test setup): %v", enumErr)
		} else {
			t.Logf("cipher enumeration completed successfully with %d ciphers", len(ciphers))
		}
	}
}
