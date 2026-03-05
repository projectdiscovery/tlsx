package ztls

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/zmap/zcrypto/tls"
)

// TestGoroutineCleanupAfterTimeouts verifies that no goroutines are leaked
// after many sequential handshake timeouts against an unresponsive server.
// This is a regression test for https://github.com/projectdiscovery/tlsx/issues/819
func TestGoroutineCleanupAfterTimeouts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Hold connection open; exits when client closes its side.
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	// Let runtime settle and record baseline goroutine count.
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	const iterations = 100
	client := &Client{}
	for i := 0; i < iterations; i++ {
		tcpConn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if err != nil {
			t.Fatalf("iteration %d: failed to dial: %v", i, err)
		}

		tlsConn := tls.Client(tcpConn, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS12,
		})

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		_ = client.tlsHandshakeWithTimeout(ctx, tlsConn, tcpConn)
		cancel()
		_ = tcpConn.Close()
	}

	// Allow server-side goroutines to notice closed connections and exit.
	runtime.GC()
	time.Sleep(500 * time.Millisecond)

	final := runtime.NumGoroutine()
	leaked := final - baseline
	t.Logf("goroutines: baseline=%d, after %d timeouts=%d, leaked=%d", baseline, iterations, final, leaked)

	// Allow a small margin for runtime goroutines, but the handshake
	// goroutines themselves must not accumulate.
	if leaked > 10 {
		t.Fatalf("goroutine leak detected: %d goroutines leaked after %d iterations (baseline=%d, final=%d)",
			leaked, iterations, baseline, final)
	}
}

// TestConcurrentHandshakeTimeouts verifies goroutine safety when many
// handshakes timeout concurrently, simulating a high-concurrency scan
// hitting unresponsive hosts (the exact production scenario from #819).
func TestConcurrentHandshakeTimeouts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Read ClientHello but never respond — exact #819 reproduction.
			// Exits when client closes its side.
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	const concurrency = 50
	const totalTimeouts = 200

	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	start := time.Now()
	for i := 0; i < totalTimeouts; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()

			tcpConn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
			if err != nil {
				return
			}

			tlsConn := tls.Client(tcpConn, &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS10,
				MaxVersion:         tls.VersionTLS12,
			})

			client := &Client{}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			_ = client.tlsHandshakeWithTimeout(ctx, tlsConn, tcpConn)
			cancel()
			_ = tcpConn.Close()
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	// Allow server-side goroutines to notice closed connections.
	runtime.GC()
	time.Sleep(500 * time.Millisecond)
	final := runtime.NumGoroutine()
	leaked := final - baseline

	throughput := float64(totalTimeouts) / elapsed.Seconds()
	t.Logf("completed %d concurrent timeouts in %v (%.1f timeouts/sec)", totalTimeouts, elapsed, throughput)
	t.Logf("goroutines: baseline=%d, final=%d, leaked=%d", baseline, final, leaked)

	if leaked > 15 {
		t.Fatalf("goroutine leak: %d goroutines leaked after %d concurrent timeouts", leaked, totalTimeouts)
	}
}

// TestHandshakeTimeoutReturnsWithinDeadline checks that each timeout
// completes within a reasonable margin of the context deadline, ensuring
// no pathological blocking occurs.
func TestHandshakeTimeoutReturnsWithinDeadline(t *testing.T) {
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
			go func(c net.Conn) {
				defer c.Close()
				<-done
			}(conn)
		}
	}()

	deadlines := []time.Duration{100 * time.Millisecond, 500 * time.Millisecond, 1 * time.Second}

	for _, deadline := range deadlines {
		t.Run(fmt.Sprintf("deadline_%v", deadline), func(t *testing.T) {
			tcpConn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
			if err != nil {
				t.Fatalf("failed to dial: %v", err)
			}
			defer tcpConn.Close()

			tlsConn := tls.Client(tcpConn, &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS10,
				MaxVersion:         tls.VersionTLS12,
			})

			client := &Client{}
			ctx, cancel := context.WithTimeout(context.Background(), deadline)
			defer cancel()

			start := time.Now()
			err = client.tlsHandshakeWithTimeout(ctx, tlsConn, tcpConn)
			elapsed := time.Since(start)

			if err == nil {
				t.Fatal("expected timeout error")
			}

			// Should complete within 2x the deadline (generous margin for CI).
			maxAllowed := deadline * 2
			if elapsed > maxAllowed {
				t.Fatalf("handshake took %v, expected within %v of deadline %v", elapsed, maxAllowed, deadline)
			}
			t.Logf("deadline=%v, actual=%v", deadline, elapsed)
		})
	}
}
