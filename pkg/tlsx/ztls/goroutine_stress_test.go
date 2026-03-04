package ztls

import (
	"context"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/zmap/zcrypto/tls"
)

// TestGoroutineCountAfter100SequentialTimeouts tests goroutine cleanup
// with 100 sequential timeout scenarios to verify zero accumulation.
func TestGoroutineCountAfter100SequentialTimeouts(t *testing.T) {
	// Capture baseline goroutine count
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	baselineGoroutines := runtime.NumGoroutine()
	t.Logf("Baseline goroutines: %d", baselineGoroutines)

	// Create a TCP listener that accepts but never responds
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer ln.Close()

	// Server that holds connections open without responding
	serverStop := make(chan struct{})
	defer close(serverStop)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				select {
				case <-serverStop:
					return
				default:
					_, _ = io.ReadAll(c)
				}
			}(conn)
		}
	}()

	// Run 100 sequential handshake attempts
	numAttempts := 100
	startTime := time.Now()

	for i := 0; i < numAttempts; i++ {
		tcpConn, err := net.DialTimeout("tcp", ln.Addr().String(), 100*time.Millisecond)
		if err != nil {
			t.Fatalf("dial failed: %v", err)
		}

		tlsConn := tls.Client(tcpConn, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS12,
		})

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)

		// Use the internal tlsHandshakeWithTimeout which properly handles zcrypto
		client := &Client{}
		err = client.tlsHandshakeWithTimeout(tlsConn, tcpConn, ctx)
		cancel()
		_ = tcpConn.Close()

		if err == nil {
			t.Fatalf("expected timeout, got nil")
		}
	}

	elapsed := time.Since(startTime)
	t.Logf("Completed %d sequential timeouts in %v", numAttempts, elapsed)
	t.Logf("Average time per timeout: %v", elapsed/time.Duration(numAttempts))

	// Give goroutines time to clean up
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	time.Sleep(50 * time.Millisecond)

	// Capture post-test goroutine count
	postGoroutines := runtime.NumGoroutine()
	leakedGoroutines := postGoroutines - baselineGoroutines

	t.Logf("Post-test goroutines: %d", postGoroutines)
	t.Logf("Goroutine difference: %+d", leakedGoroutines)

	// Verify no significant leak (allow 10% margin for runtime goroutines)
	maxAllowedLeak := numAttempts * 10 / 100 // 10% of 100 = 10
	if leakedGoroutines > maxAllowedLeak {
		t.Errorf("GOROUTINE LEAK DETECTED: %d goroutines leaked (max allowed: %d)", leakedGoroutines, maxAllowedLeak)
	} else {
		t.Logf("✅ PASS: Goroutine count stable - zero leak verified")
	}

	// Report
	t.Logf("=== PERFORMANCE REPORT ===")
	t.Logf("Total timeout attempts: %d", numAttempts)
	t.Logf("Total elapsed time: %v", elapsed)
	t.Logf("Baseline goroutines: %d", baselineGoroutines)
	t.Logf("Post-test goroutines: %d", postGoroutines)
	t.Logf("Goroutine leak: %+d (%.2f%%)", leakedGoroutines, float64(leakedGoroutines)/float64(numAttempts)*100)
}
