package ztls_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/ztls"
)

// TestHandshakeTimeout verifies that TLS handshake properly times out
// when the server doesn't respond within the timeout period.
// This test addresses issue #819 where tlsx would hang indefinitely.
func TestHandshakeTimeout(t *testing.T) {
	// Create a TLS server that delays the handshake
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Simulate a slow/hanging server by not doing the TLS handshake
		// Just wait for 10 seconds (longer than our timeout)
		time.Sleep(10 * time.Second)
	}()

	// Parse the listener address
	addr := listener.Addr().String()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("failed to parse address: %v", err)
	}

	// Create the client with a short timeout
	dialer, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
	if err != nil {
		t.Fatalf("failed to create dialer: %v", err)
	}
	defer dialer.Close()

	clientOpts := &clients.Options{
		Fastdialer: dialer,
		Timeout:    2, // 2 second timeout
	}

	client, err := ztls.New(clientOpts)
	if err != nil {
		t.Fatalf("failed to create ztls client: %v", err)
	}

	// Try to connect - this should timeout, not hang
	start := time.Now()
	_, err = client.ConnectWithOptions(host, "", port, clients.ConnectOptions{})
	elapsed := time.Since(start)

	// The operation should complete within a reasonable time (timeout + some buffer)
	// It should NOT hang for 10+ seconds
	if elapsed > 5*time.Second {
		t.Errorf("connection took too long (%v), possible hang detected", elapsed)
	}

	// We expect an error (timeout or connection error)
	if err == nil {
		t.Error("expected error but got none")
	}

	t.Logf("connection properly timed out after %v with error: %v", elapsed, err)
}

// TestCipherEnumerationDoesNotHang verifies that cipher enumeration doesn't hang indefinitely
// even when the server doesn't respond properly. This is a regression test for issue #819.
func TestCipherEnumerationDoesNotHang(t *testing.T) {
	// Create a server that accepts connections but doesn't complete TLS handshake
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	// Server goroutine that accepts but stalls
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Don't close - let the client deal with the timeout
			go func(c net.Conn) {
				defer c.Close()
				time.Sleep(30 * time.Second)
			}(conn)
		}
	}()

	addr := listener.Addr().String()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("failed to parse address: %v", err)
	}

	dialer, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
	if err != nil {
		t.Fatalf("failed to create dialer: %v", err)
	}
	defer dialer.Close()

	clientOpts := &clients.Options{
		Fastdialer:        dialer,
		Timeout:           1, // Very short timeout
		CipherConcurrency: 10,
	}

	client, err := ztls.New(clientOpts)
	if err != nil {
		t.Fatalf("failed to create ztls client: %v", err)
	}

	// Try cipher enumeration with only a few ciphers to keep test fast
	// The key is that it should complete (possibly with empty results), not hang
	start := time.Now()

	// Set a reasonable deadline for the entire test
	// With 1s timeout per operation and pool-level timeouts, this should complete quickly
	done := make(chan []string)
	go func() {
		// Only test with TLS 1.2 which has a limited cipher set
		ciphers, _ := client.EnumerateCiphers(host, "", port, clients.ConnectOptions{
			VersionTLS: "tls12",
		})
		done <- ciphers
	}()

	select {
	case ciphers := <-done:
		elapsed := time.Since(start)
		// The enumeration should complete. Since the server doesn't respond,
		// we expect no ciphers to be found, but the important thing is it didn't hang.
		t.Logf("cipher enumeration completed after %v with %d ciphers found", elapsed, len(ciphers))

		// Verify it completed in a reasonable time (should be much less than before the fix)
		// With the fix, each failed cipher attempt should timeout quickly
		// We give it 30 seconds total which is generous but ensures no indefinite hang
		if elapsed > 30*time.Second {
			t.Errorf("cipher enumeration took too long (%v), possible hang or missing timeout", elapsed)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("cipher enumeration appears to be hanging - this is the bug we're trying to fix")
	}
}

// generateSelfSignedCert generates a self-signed certificate for testing
func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}
