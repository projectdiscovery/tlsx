package ztls_test

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
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
				t.Errorf("error parsing test server url: %s", err)
			}

			connectOpts := clients.ConnectOptions{
				VersionTLS: tc.tlsVersion,
			}

			dialer, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
			if err != nil {
				t.Errorf("error initializing dialer: %s", err)
			}

			clientOpts := &clients.Options{
				Fastdialer: dialer,
			}

			client, err := ztls.New(clientOpts)
			if err != nil {
				t.Errorf("error initializing ztls client: %s", err)
			}

			host := parsedUrl.Hostname()
			resp, err := client.ConnectWithOptions(host, host, parsedUrl.Port(), connectOpts)
			if err != nil {
				t.Errorf("client ConnectWithOptions call failed: %s", err)
			}

			actualResult := resp.ClientCertRequired

			if tc.expectedResult != nil && actualResult == nil {
				t.Errorf("expected isClientCertRequired = %t but received nil", *tc.expectedResult)
			} else if tc.expectedResult == nil && actualResult != nil {
				t.Errorf("expected isClientCertRequired = nil but received %t", *actualResult)
			} else if *tc.expectedResult != *actualResult {
				t.Errorf("expected isClientCertRequired = %t but received %t", *tc.expectedResult, *actualResult)
			}
		})
	}
}

func boolPtr(v bool) *bool {
	return &v
}
