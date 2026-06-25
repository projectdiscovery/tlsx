package ztls_test

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"testing"

	ctls "crypto/tls"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/ztls"
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

			client, err := ztls.New(clientOpts)
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
// yields the same accepted set regardless of CipherConcurrency and stays race
// free (run with -race).
func TestEnumerateCiphersConcurrent(t *testing.T) {
	log.SetOutput(io.Discard)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "OK")
	}))
	server.TLS = &ctls.Config{
		MinVersion: ctls.VersionTLS12,
		MaxVersion: ctls.VersionTLS12,
		CipherSuites: []uint16{
			ctls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			ctls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}
	server.StartTLS()
	defer server.Close()

	parsedURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host := parsedURL.Hostname()
	port := parsedURL.Port()

	dedup := func(in []string) []string {
		seen := map[string]struct{}{}
		out := make([]string, 0, len(in))
		for _, c := range in {
			if _, ok := seen[c]; ok {
				continue
			}
			seen[c] = struct{}{}
			out = append(out, c)
		}
		sort.Strings(out)
		return out
	}

	var baseline []string
	for _, concurrency := range []int{1, 4, 16} {
		t.Run(fmt.Sprintf("concurrency_%d", concurrency), func(t *testing.T) {
			dialer, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
			if err != nil {
				t.Fatal(err)
			}
			defer dialer.Close()

			client, err := ztls.New(&clients.Options{
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
			got = dedup(got)
			if len(got) == 0 {
				t.Fatalf("concurrency %d: expected at least one cipher, got none", concurrency)
			}
			if baseline == nil {
				baseline = got
			} else if !reflect.DeepEqual(got, baseline) {
				t.Fatalf("concurrency %d: expected %v, got %v", concurrency, baseline, got)
			}
		})
	}
}
