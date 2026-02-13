package ztls

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/zmap/zcrypto/tls"
)

func TestTLSHandshakeWithTimeout_ContextCancellation(t *testing.T) {
	// Create a TCP listener that accepts but never responds (simulates hanging server).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	// Accept connections but do nothing — forces the TLS handshake to hang.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Hold the connection open but never send TLS data.
			defer conn.Close()
		}
	}()

	rawConn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}

	client := &Client{
		options: &clients.Options{Timeout: 5},
	}

	tlsConn := tls.Client(rawConn, &tls.Config{InsecureSkipVerify: true})

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	start := time.Now()
	err = client.tlsHandshakeWithTimeout(tlsConn, rawConn, ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}

	// The handshake should be interrupted within ~500ms (the context timeout),
	// not hang indefinitely. Allow up to 2 seconds for CI jitter.
	if elapsed > 2*time.Second {
		t.Fatalf("handshake took %v, expected to be interrupted by context timeout (~500ms)", elapsed)
	}
}

func TestCipherHandshakeContext_UsesConfiguredTimeout(t *testing.T) {
	client := &Client{
		options: &clients.Options{Timeout: 3},
	}

	ctx, cancel := client.cipherHandshakeContext()
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("expected context with deadline")
	}

	remaining := time.Until(deadline)
	if remaining < 2*time.Second || remaining > 4*time.Second {
		t.Fatalf("expected ~3s deadline, got %v remaining", remaining)
	}
}

func TestCipherHandshakeContext_DefaultsWhenZero(t *testing.T) {
	client := &Client{
		options: &clients.Options{Timeout: 0},
	}

	ctx, cancel := client.cipherHandshakeContext()
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("expected context with deadline")
	}

	remaining := time.Until(deadline)
	if remaining < 9*time.Second || remaining > 11*time.Second {
		t.Fatalf("expected ~10s default deadline, got %v remaining", remaining)
	}
}
