package ztls

import (
	"context"
	"net"
	"testing"
	"time"

	ztls "github.com/zmap/zcrypto/tls"
)

func TestTLSHandshakeWithTimeout_ContextDeadline(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	conn := ztls.Client(clientConn, &ztls.Config{ServerName: "example.com", InsecureSkipVerify: true})
	client := &Client{}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := client.tlsHandshakeWithTimeout(ctx, conn)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("expected timeout error, got nil")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("handshake timeout took too long: %s", elapsed)
	}
}
