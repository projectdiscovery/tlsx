package ztls

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/zmap/zcrypto/tls"
)

func TestTLSHandshakeWithTimeoutReturnsOnContextDeadline(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()

	tlsConn := tls.Client(clientConn, &tls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
	})

	client := &Client{}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- client.tlsHandshakeWithTimeout(tlsConn, ctx)
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("expected timeout error, got nil")
		}
		if time.Since(start) > time.Second {
			t.Fatalf("handshake timeout took too long: %s", time.Since(start))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handshake did not return on context deadline")
	}
}
