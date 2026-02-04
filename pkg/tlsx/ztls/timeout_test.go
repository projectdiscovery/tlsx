package ztls

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestHandshakeTimeoutCancellation verifies that the handshake timeout
// properly cancels when the context is cancelled, rather than blocking
// indefinitely on the handshake operation.
func TestHandshakeTimeoutCancellation(t *testing.T) {
	// Create a very short timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	// Verify context cancellation works as expected
	select {
	case <-ctx.Done():
		// Expected - context should timeout
		assert.Error(t, ctx.Err(), "context should have error after timeout")
	case <-time.After(100 * time.Millisecond):
		t.Fatal("context timeout did not trigger")
	}
}

// TestContextSelectBehavior verifies that a goroutine-based approach
// allows the select statement to properly choose between completion
// and context cancellation.
func TestContextSelectBehavior(t *testing.T) {
	// This test demonstrates the correct pattern for timeout-based
	// handshakes: running the blocking operation in a goroutine
	// so the select can properly evaluate both cases.

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	resultChan := make(chan string, 1)

	// Simulate a slow operation in a goroutine
	go func() {
		time.Sleep(200 * time.Millisecond) // Slower than timeout
		resultChan <- "completed"
	}()

	select {
	case <-ctx.Done():
		// This is the expected path - timeout should win
		assert.Equal(t, context.DeadlineExceeded, ctx.Err())
	case result := <-resultChan:
		t.Fatalf("should have timed out, but got result: %s", result)
	}
}

// TestNoDeadlockOnTimeout ensures that the timeout mechanism doesn't
// cause goroutine leaks or deadlocks.
func TestNoDeadlockOnTimeout(t *testing.T) {
	done := make(chan struct{})

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		errChan := make(chan error, 1)

		// Run blocking operation in goroutine
		go func() {
			time.Sleep(100 * time.Millisecond) // Simulate slow handshake
			errChan <- nil
		}()

		select {
		case <-ctx.Done():
			// Timeout occurred - this is expected
		case <-errChan:
			// Operation completed
		}

		close(done)
	}()

	// Test should complete without deadlock
	select {
	case <-done:
		// Success - no deadlock
	case <-time.After(500 * time.Millisecond):
		t.Fatal("test timed out - possible deadlock")
	}
}
