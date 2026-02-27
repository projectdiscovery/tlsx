package ztls

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/zmap/zcrypto/tls"
)

// TestHandshakeTimeout validates that tlsHandshakeWithTimeout respects the
// context deadline instead of blocking forever. We spin up a raw TCP listener
// that accepts connections but never speaks TLS -- exactly the scenario that
// triggers the hang reported in issue #819.
func TestHandshakeTimeout(t *testing.T) {
	// Start a listener that accepts TCP but does nothing (simulates a host
	// whose TLS stack is unresponsive or extremely slow).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test listener: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			// Hold the connection open but never write anything.
			// This forces the TLS handshake to block on read.
			go func(c net.Conn) {
				<-time.After(30 * time.Second)
				c.Close()
			}(conn)
		}
	}()

	// Connect to the silent listener
	rawConn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to test listener: %v", err)
	}
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "localhost",
	})

	client := &Client{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	err = client.tlsHandshakeWithTimeout(tlsConn, ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected handshake to fail with timeout, but it succeeded")
	}

	// The handshake should bail out within a reasonable margin of the 2s deadline.
	// Give it up to 4s to account for slow CI runners.
	if elapsed > 4*time.Second {
		t.Fatalf("handshake took %v, expected it to respect the 2s deadline", elapsed)
	}

	t.Logf("handshake correctly timed out in %v with error: %v", elapsed, err)
}
