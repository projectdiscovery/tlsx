package ztls

import (
	"context"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/zmap/zcrypto/tls"
)

func TestHandshakeTimeoutLeak(t *testing.T) {
	// Start a listener that accepts but doesn't respond
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close() //nolint:errcheck

	var conns []net.Conn
	var mu sync.Mutex
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
	})

	addr := l.Addr().String()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}

	dialer, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
	if err != nil {
		t.Fatal(err)
	}
	defer dialer.Close()

	options := &clients.Options{
		Fastdialer: dialer,
		Timeout:    1,
	}
	client, err := New(options)
	if err != nil {
		t.Fatal(err)
	}

	before := runtime.NumGoroutine()

	iterations := 50
	for i := 0; i < iterations; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		rawConn, err := net.DialTimeout("tcp", addr, 1*time.Second)
		if err != nil {
			cancel()
			continue
		}
		
		config, err := client.getConfig(host, host, port, clients.ConnectOptions{})
		if err != nil {
			rawConn.Close() //nolint:errcheck
			cancel()
			continue
		}
		tlsConn := tls.Client(rawConn, config)
		
		_ = client.tlsHandshakeWithTimeout(tlsConn, rawConn, ctx)
		_ = tlsConn.Close()
		cancel()
	}

	// Give some time for goroutines to exit
	time.Sleep(1 * time.Second)
	runtime.GC()
	time.Sleep(500 * time.Millisecond)

	after := runtime.NumGoroutine()
	
	// NumGoroutine might include other things, but it shouldn't be close to 'iterations' if we fixed the leak.
	if after-before > 5 {
		t.Errorf("Potential goroutine leak detected: started with %d, ended with %d (iterations: %d)", before, after, iterations)
	}
}

func TestUnresponsiveServer(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close() //nolint:errcheck

	var conns []net.Conn
	var mu sync.Mutex
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
	})

	addr := l.Addr().String()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}

	dialer, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
	if err != nil {
		t.Fatal(err)
	}
	defer dialer.Close()

	client, err := New(&clients.Options{Fastdialer: dialer, Timeout: 1})
	if err != nil {
		t.Fatal(err)
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	config, err := client.getConfig(host, host, port, clients.ConnectOptions{})
	if err != nil {
		rawConn.Close() //nolint:errcheck
		t.Fatal(err)
	}
	tlsConn := tls.Client(rawConn, config)

	start := time.Now()
	err = client.tlsHandshakeWithTimeout(tlsConn, rawConn, ctx)
	duration := time.Since(start)

	if err == nil {
		t.Error("Expected timeout error, got nil")
	}
	if duration > 1*time.Second {
		t.Errorf("Handshake took too long: %v", duration)
	}
}

func TestSlowServer(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close() //nolint:errcheck

	go func() {
		conn, _ := l.Accept()
		if conn != nil {
			// Read ClientHello
			buf := make([]byte, 1024)
			_, _ = conn.Read(buf)
			// Delay response indefinitely
			time.Sleep(2 * time.Second)
			_ = conn.Close()
		}
	}()

	addr := l.Addr().String()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}

	dialer, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
	if err != nil {
		t.Fatal(err)
	}
	defer dialer.Close()

	client, err := New(&clients.Options{Fastdialer: dialer, Timeout: 1})
	if err != nil {
		t.Fatal(err)
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	config, err := client.getConfig(host, host, port, clients.ConnectOptions{})
	if err != nil {
		rawConn.Close() //nolint:errcheck
		t.Fatal(err)
	}
	tlsConn := tls.Client(rawConn, config)

	start := time.Now()
	err = client.tlsHandshakeWithTimeout(tlsConn, rawConn, ctx)
	duration := time.Since(start)

	if err == nil {
		t.Error("Expected timeout error, got nil")
	}
	if duration > 1*time.Second {
		t.Errorf("Handshake took too long: %v", duration)
	}
}
