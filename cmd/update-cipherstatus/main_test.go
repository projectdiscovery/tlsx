package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSkipOverwriteKeepsFilledDataset(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "cipherstatus_data.json")

	filled := make(map[string]string, minExpectedCiphers)
	for i := 0; i < minExpectedCiphers; i++ {
		filled[fmt.Sprintf("TLS_TEST_CIPHER_%d", i)] = "Secure"
	}
	bin, err := json.Marshal(filled)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bin, 0600); err != nil {
		t.Fatal(err)
	}

	if !skipOverwrite(path, "simulated empty fetch") {
		t.Fatal("expected skip when existing dataset is filled")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(bin) {
		t.Fatal("existing dataset was modified")
	}
}

func TestSkipOverwriteRejectsEmptyExisting(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "cipherstatus_data.json")
	if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if skipOverwrite(path, "empty refresh") {
		t.Fatal("should not skip when existing dataset is empty")
	}
}

// sampleCipherSuiteAPIPayload mirrors https://ciphersuite.info/api/cs/ shape:
// {"ciphersuites":[{"TLS_...":{"openssl_name":"...","gnutls_name":"...","security":"..."}}]}
const sampleCipherSuiteAPIPayload = `{
  "ciphersuites": [
    {
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": {
        "openssl_name": "ECDHE-RSA-AES128-GCM-SHA256",
        "gnutls_name": "TLS_ECDHE_RSA_AES_128_GCM_SHA256",
        "security": "secure"
      }
    },
    {
      "TLS_RSA_WITH_RC4_128_MD5": {
        "openssl_name": "RC4-MD5",
        "gnutls_name": "TLS_RSA_ARCFOUR_128_MD5",
        "security": "insecure"
      }
    },
    {
      "TLS_AES_128_GCM_SHA256": {
        "openssl_name": "TLS_AES_128_GCM_SHA256",
        "gnutls_name": "TLS_AES_128_GCM_SHA256",
        "security": "recommended"
      }
    },
    {
      "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA": {
        "openssl_name": "ECDHE-RSA-DES-CBC3-SHA",
        "gnutls_name": "TLS_ECDHE_RSA_3DES_EDE_CBC_SHA1",
        "security": "weak"
      }
    },
    {
      "TLS_SKIP_UNKNOWN_LEVEL": {
        "openssl_name": "SKIP-ME",
        "gnutls_name": "",
        "security": "experimental"
      }
    }
  ]
}`

func TestLoadCiphersFromReaderMapsAliases(t *testing.T) {
	t.Parallel()

	got, err := loadCiphersFromReader(strings.NewReader(sampleCipherSuiteAPIPayload))
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": "Secure",
		"ECDHE-RSA-AES128-GCM-SHA256":           "Secure",
		"TLS_ECDHE_RSA_AES_128_GCM_SHA256":      "Secure",
		"TLS_RSA_WITH_RC4_128_MD5":              "Insecure",
		"RC4-MD5":                               "Insecure",
		"TLS_RSA_ARCFOUR_128_MD5":               "Insecure",
		"TLS_AES_128_GCM_SHA256":                "Recommended",
		"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":   "Weak",
		"ECDHE-RSA-DES-CBC3-SHA":                "Weak",
		"TLS_ECDHE_RSA_3DES_EDE_CBC_SHA1":       "Weak",
	}
	for name, level := range want {
		if got[name] != level {
			t.Fatalf("%s: got %q want %q", name, got[name], level)
		}
	}
	if _, ok := got["TLS_SKIP_UNKNOWN_LEVEL"]; ok {
		t.Fatal("unknown security level should be skipped")
	}
	if _, ok := got["SKIP-ME"]; ok {
		t.Fatal("alias of skipped suite should not be present")
	}
}

func TestLoadCiphersFromReaderRejectsInvalidJSON(t *testing.T) {
	t.Parallel()

	if _, err := loadCiphersFromReader(strings.NewReader(`{not-json`)); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestFetchAndLoadCiphersHTTP(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(sampleCipherSuiteAPIPayload))
	}))
	t.Cleanup(srv.Close)

	got, err := fetchAndLoadCiphers(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"] != "Secure" {
		t.Fatalf("unexpected level: %q", got["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"])
	}
	if got["ECDHE-RSA-AES128-GCM-SHA256"] != "Secure" {
		t.Fatalf("openssl alias missing/wrong: %q", got["ECDHE-RSA-AES128-GCM-SHA256"])
	}
}

func TestFetchAndLoadCiphersHTTPErrorStatus(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)

	if _, err := fetchAndLoadCiphers(srv.URL); err == nil {
		t.Fatal("expected status error")
	}
}
