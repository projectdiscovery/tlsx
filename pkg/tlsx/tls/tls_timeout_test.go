package tls

import (
	"testing"
	"time"

	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
)

func TestCipherHandshakeContext_UsesConfiguredTimeout(t *testing.T) {
	client := &Client{
		options: &clients.Options{Timeout: 3},
	}

	ctx, cancel := client.cipherHandshakeContext()
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("expected context with deadline")
	}

	remaining := time.Until(deadline)
	if remaining < 2*time.Second || remaining > 4*time.Second {
		t.Fatalf("expected ~3s deadline, got %v remaining", remaining)
	}
}

func TestCipherHandshakeContext_DefaultsWhenZero(t *testing.T) {
	client := &Client{
		options: &clients.Options{Timeout: 0},
	}

	ctx, cancel := client.cipherHandshakeContext()
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("expected context with deadline")
	}

	remaining := time.Until(deadline)
	if remaining < 9*time.Second || remaining > 11*time.Second {
		t.Fatalf("expected ~10s default deadline, got %v remaining", remaining)
	}
}
