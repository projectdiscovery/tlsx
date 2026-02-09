package ztls

import (
	"context"
	"net"
	"testing"
	"time"
	"strings"

	"github.com/zmap/zcrypto/tls"
)

// hangingConn is a net.Conn that blocks on Read and Write
type hangingConn struct {
	net.Conn
}

func (h hangingConn) Read(b []byte) (n int, err error) {
	select {}
}

func (h hangingConn) Write(b []byte) (n int, err error) {
	select {}
}

func TestTLSHandshakeHang(t *testing.T) {
	// create a pipe to simulate a connection
	// we wrap client side to ensure it hangs if it tries to read/write
	clientConn, _ := net.Pipe()
	defer clientConn.Close()

	hanging := hangingConn{Conn: clientConn}

	// create a tls connection using the hanging connection
	// we don't need a real server because we want to test the client-side timeout
	// when the "network" hangs during handshake hello or similar.
	config := &tls.Config{
		InsecureSkipVerify: true,
	}
	tlsConn := tls.Client(hanging, config)

	// Create a dummy client just to call the method
	client := &Client{}

	// context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := client.tlsHandshakeWithTimeout(tlsConn, ctx)
	duration := time.Since(start)

	// Check if it respected timeout
	if duration > 1*time.Second {
		t.Errorf("Handshake took too long: %v, expected ~200ms", duration)
	}

	if err == nil {
		t.Error("Expected timeout error, got nil")
	} else {
		// verify it's the right error
		if !strings.Contains(err.Error(), "timeout") {
			t.Errorf("Expected timeout error, got: %v", err)
		}
	}
}
