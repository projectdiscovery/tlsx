package ztls

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/zmap/zcrypto/tls"
)

// TestHandshakeTimeoutWithUnresponsiveServer verifies that tlsHandshakeWithTimeout
// returns within the context deadline when the remote peer never responds.
// This is a regression test for https://github.com/projectdiscovery/tlsx/issues/819
// where zcrypto's Handshake() blocked the select, preventing ctx.Done() from firing.
func TestHandshakeTimeoutWithUnresponsiveServer(t *testing.T) {
	// Start a TCP listener that accepts connections but never sends TLS data,
	// simulating hosts that cause indefinite hangs.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Hold the connection open without responding.
			go func(c net.Conn) {
				defer c.Close()
				<-done
			}(conn)
		}
	}()

	// Connect to the unresponsive listener.
	tcpConn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial listener: %v", err)
	}

	tlsConn := tls.Client(tcpConn, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS12,
	})

	client := &Client{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	err = client.tlsHandshakeWithTimeout(ctx, tlsConn, tcpConn)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected handshake to fail with timeout, got nil error")
	}

	// The function must return within a reasonable margin of the 2s deadline.
	// Before the fix, this would hang indefinitely because zcrypto's Handshake()
	// was called synchronously inside the select case expression.
	if elapsed > 5*time.Second {
		t.Fatalf("handshake took %v — expected it to respect the 2s context deadline", elapsed)
	}

	t.Logf("handshake correctly timed out after %v: %v", elapsed, err)
}

// TestHandshakeTimeoutWithSlowServer uses a server that reads the ClientHello
// and then stalls, which is the exact pattern seen in production with certain
// TLS configurations (issue #819).
func TestHandshakeTimeoutWithSlowServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Read the ClientHello but never respond.
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.ReadAll(c)
				<-done
			}(conn)
		}
	}()

	tcpConn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial listener: %v", err)
	}

	tlsConn := tls.Client(tcpConn, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS12,
	})

	client := &Client{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	err = client.tlsHandshakeWithTimeout(ctx, tlsConn, tcpConn)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected handshake to fail with timeout, got nil error")
	}

	if elapsed > 5*time.Second {
		t.Fatalf("handshake took %v — expected it to respect the 2s context deadline", elapsed)
	}

	t.Logf("slow-server handshake correctly timed out after %v: %v", elapsed, err)
}
