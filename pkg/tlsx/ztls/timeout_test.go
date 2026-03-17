package ztls

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/zmap/zcrypto/tls"
)

// TestHandshakeTimeout verifies that tlsHandshakeWithTimeout returns promptly
// when the context deadline is reached rather than hanging indefinitely.
// This is the regression test for issue #819.
func TestHandshakeTimeout(t *testing.T) {
	// Start a TCP listener that accepts connections but never sends data,
	// simulating the hosts that cause tlsx to hang indefinitely.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	// Accept connections in the background so the dial succeeds,
	// but never do anything with them (simulating a hanging server).
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// hold the connection open, never respond
			t.Cleanup(func() { conn.Close() })
		}
	}()

	// Dial the hanging server.
	rawConn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	t.Cleanup(func() { rawConn.Close() })

	// Wrap in a ztls TLS connection.
	tlsConn := tls.Client(rawConn, &tls.Config{InsecureSkipVerify: true})

	// Use a short context deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Create a minimal Client (receiver is not used by tlsHandshakeWithTimeout).
	c := &Client{}

	start := time.Now()
	err = c.tlsHandshakeWithTimeout(tlsConn, rawConn, ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}

	// Must complete within 2 seconds (generous margin above the 500ms deadline).
	if elapsed > 2*time.Second {
		t.Fatalf("handshake took %v, expected to timeout around 500ms", elapsed)
	}

	t.Logf("handshake timed out correctly in %v", elapsed)
}
