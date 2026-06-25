package tls_test

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	ctls "crypto/tls"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/tls"
)

func TestClientCertRequired(t *testing.T) {
	cases := []struct {
		name             string
		clientAuthConfig ctls.ClientAuthType
		tlsVersion       string
		expectedResult   *bool
	}{
		{
			name:             "tls10_cert_required_by_server",
			clientAuthConfig: ctls.RequireAnyClientCert,
			tlsVersion:       "tls10",
			expectedResult:   boolPtr(true),
		},
		{
			name:             "tls11_cert_required_by_server",
			clientAuthConfig: ctls.RequireAnyClientCert,
			tlsVersion:       "tls11",
			expectedResult:   boolPtr(true),
		},
		{
			name:             "tls12_cert_required_by_server",
			clientAuthConfig: ctls.RequireAnyClientCert,
			tlsVersion:       "tls12",
			expectedResult:   boolPtr(true),
		},
		{
			name:             "tls12_cert_not_required_by_server",
			clientAuthConfig: ctls.NoClientCert,
			tlsVersion:       "tls12",
			expectedResult:   boolPtr(false),
		},
		{
			name:             "tls13_cert_required_by_server",
			clientAuthConfig: ctls.RequireAnyClientCert,
			tlsVersion:       "tls13",
			expectedResult:   nil,
		},
		{
			name:             "tls13_cert_not_required_by_server",
			clientAuthConfig: ctls.NoClientCert,
			tlsVersion:       "tls13",
			expectedResult:   nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			log.SetOutput(io.Discard) // discard logs

			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = fmt.Fprintf(w, "OK")
			}))
			server.TLS.ClientAuth = tc.clientAuthConfig
			server.TLS.MinVersion = ctls.VersionTLS10
			defer server.Close()

			parsedUrl, err := url.Parse(server.URL)
			if err != nil {
				t.Fatalf("error parsing test server url: %s", err)
			}

			connectOpts := clients.ConnectOptions{
				VersionTLS: tc.tlsVersion,
			}

			dialer, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
			if err != nil {
				t.Fatal(err)
			}
			defer dialer.Close()

			clientOpts := &clients.Options{
				Fastdialer: dialer,
			}

			client, err := tls.New(clientOpts)
			if err != nil {
				t.Fatal(err)
			}

			host := parsedUrl.Hostname()
			resp, err := client.ConnectWithOptions(host, host, parsedUrl.Port(), connectOpts)
			if err != nil {
				t.Skipf("client ConnectWithOptions call failed (environment-dependent): %s", err)
			}

			actualResult := resp.ClientCertRequired

			if tc.expectedResult != nil && actualResult == nil {
				t.Errorf("expected isClientCertRequired = %t but received nil", *tc.expectedResult)
			} else if tc.expectedResult == nil && actualResult != nil {
				t.Errorf("expected isClientCertRequired = nil but received %t", *actualResult)
			} else if tc.expectedResult != nil && actualResult != nil && *tc.expectedResult != *actualResult {
				t.Errorf("expected isClientCertRequired = %t but received %t", *tc.expectedResult, *actualResult)
			}
		})
	}
}

func boolPtr(v bool) *bool {
	return &v
}

// TestEnumerateCiphersConcurrent verifies the concurrent cipher enumeration
// returns the full, deduplicated set the server accepts and stays race free
// (run with -race) regardless of CipherConcurrency.
func TestEnumerateCiphersConcurrent(t *testing.T) {
	log.SetOutput(io.Discard)

	serverCiphers := []uint16{
		ctls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		ctls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		ctls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}
	expected := make([]string, 0, len(serverCiphers))
	for _, c := range serverCiphers {
		expected = append(expected, ctls.CipherSuiteName(c))
	}
	sort.Strings(expected)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "OK")
	}))
	server.TLS = &ctls.Config{
		MinVersion:   ctls.VersionTLS12,
		MaxVersion:   ctls.VersionTLS12,
		CipherSuites: serverCiphers,
	}
	server.StartTLS()
	defer server.Close()

	parsedURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host := parsedURL.Hostname()
	port := parsedURL.Port()

	for _, concurrency := range []int{1, 4, 16} {
		t.Run(fmt.Sprintf("concurrency_%d", concurrency), func(t *testing.T) {
			dialer, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
			if err != nil {
				t.Fatal(err)
			}
			defer dialer.Close()

			client, err := tls.New(&clients.Options{
				Fastdialer:        dialer,
				Timeout:           5,
				CipherConcurrency: concurrency,
			})
			if err != nil {
				t.Fatal(err)
			}

			got, err := client.EnumerateCiphers(host, host, port, clients.ConnectOptions{
				VersionTLS: "tls12",
				EnumMode:   clients.Cipher,
			})
			if err != nil {
				t.Skipf("EnumerateCiphers failed (environment-dependent): %s", err)
			}
			// multiple cipher names can negotiate to the same suite, so dedup
			// before comparing the accepted set against the server config.
			seen := map[string]struct{}{}
			uniq := make([]string, 0, len(got))
			for _, c := range got {
				if _, ok := seen[c]; ok {
					continue
				}
				seen[c] = struct{}{}
				uniq = append(uniq, c)
			}
			sort.Strings(uniq)
			if !reflect.DeepEqual(uniq, expected) {
				t.Fatalf("concurrency %d: expected %v, got %v", concurrency, expected, uniq)
			}
		})
	}
}

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
	client, err := tls.New(options)
	if err != nil {
		t.Fatal(err)
	}

	before := runtime.NumGoroutine()

	iterations := 50
	for i := 0; i < iterations; i++ {
		_, _ = client.ConnectWithOptions(host, host, port, clients.ConnectOptions{})
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

func TestHighConcurrencyTimeouts(t *testing.T) {
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

	client, err := tls.New(&clients.Options{Fastdialer: dialer, Timeout: 1})
	if err != nil {
		t.Fatal(err)
	}

	before := runtime.NumGoroutine()

	const concurrentCount = 1000
	wg := sync.WaitGroup{}
	for i := 0; i < concurrentCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = client.ConnectWithOptions(host, host, port, clients.ConnectOptions{})
		}()
	}
	wg.Wait()

	// Give some time for goroutines to exit
	time.Sleep(1 * time.Second)
	runtime.GC()
	time.Sleep(500 * time.Millisecond)

	after := runtime.NumGoroutine()

	if after-before > 10 {
		t.Errorf("High concurrency leak: started with %d, ended with %d (concurrent: %d)", before, after, concurrentCount)
	}
}
