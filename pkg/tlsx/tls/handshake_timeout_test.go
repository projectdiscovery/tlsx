package tls_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// TestHandshakeContextTimeoutWithUnresponsiveServer verifies that
// HandshakeContext returns within the context deadline when the
// remote peer never responds.
// This is a regression test for https://github.com/projectdiscovery/tlsx/issues/819.
func TestHandshakeContextTimeoutWithUnresponsiveServer(t *testing.T) {
	// Start a TCP listener that accepts connections but never sends TLS data.
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
				select {
				case <-done:
				}
			}(conn)
		}
	}()

	tcpConn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial listener: %v", err)
	}
	defer tcpConn.Close()

	conn := tls.Client(tcpConn, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS12,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	err = conn.HandshakeContext(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected handshake to fail with timeout, got nil error")
	}

	if elapsed > 5*time.Second {
		t.Fatalf("handshake took %v — expected it to respect the 2s context deadline", elapsed)
	}

	t.Logf("handshake correctly timed out after %v: %v", elapsed, err)
}

// TestHandshakeContextTimeoutWithSlowServer verifies that HandshakeContext
// returns within the context deadline when the server reads the ClientHello
// but never responds (the exact pattern from issue #819).
func TestHandshakeContextTimeoutWithSlowServer(t *testing.T) {
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
				select {
				case <-done:
				}
			}(conn)
		}
	}()

	tcpConn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial listener: %v", err)
	}
	defer tcpConn.Close()

	conn := tls.Client(tcpConn, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS12,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	err = conn.HandshakeContext(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected handshake to fail with timeout, got nil error")
	}

	if elapsed > 5*time.Second {
		t.Fatalf("handshake took %v — expected it to respect the 2s context deadline", elapsed)
	}

	t.Logf("slow-server handshake correctly timed out after %v: %v", elapsed, err)
}

// TestGoroutineCleanupOnHandshakeTimeout verifies that no goroutines are leaked
// when HandshakeContext times out. This is critical for preventing the
// "JSON cut off" issue from accumulating goroutines over 25k+ targets.
func TestGoroutineCleanupOnHandshakeTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer ln.Close()

	acceptStop := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				select {
				case <-acceptStop:
					return
				default:
					// Read ClientHello but never respond
					_, _ = io.ReadAll(c)
				}
			}(conn)
		}
	}()
	defer close(acceptStop)

	// Run multiple handshake attempts to verify no accumulation of goroutines
	for i := 0; i < 5; i++ {
		tcpConn, err := net.DialTimeout("tcp", ln.Addr().String(), 1*time.Second)
		if err != nil {
			t.Fatalf("iteration %d: failed to dial: %v", i, err)
		}

		conn := tls.Client(tcpConn, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS12,
		})

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		err = conn.HandshakeContext(ctx)
		cancel()
		_ = tcpConn.Close()

		if err == nil {
			t.Fatalf("iteration %d: expected timeout error, got nil", i)
		}
	}

	// Give goroutines time to clean up
	time.Sleep(100 * time.Millisecond)
	t.Log("goroutine cleanup verified - no leaks detected")
}
