package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
)

// cipherSuiteAPI is the JSON API of https://ciphersuite.info and is the source
// of truth for cipher security levels.
const cipherSuiteAPI = "https://ciphersuite.info/api/cs/"

// minExpectedCiphers guards against overwriting the dataset with an empty or
// truncated response. Without it a silent upstream change writes `{}` and every
// cipher is reported as `unknown` by cipher-enum.
const minExpectedCiphers = 300

// securityLevels maps the security levels returned by the API to the levels
// expected by assets.CipherSecLevel consumers.
var securityLevels = map[string]string{
	"recommended": "Recommended",
	"secure":      "Secure",
	"weak":        "Weak",
	"insecure":    "Insecure",
}

type cipherSuite struct {
	// OpenSSLName and GnuTLSName are the aliases the openssl and ztls clients
	// enumerate with, they map to the same security level as the IANA name.
	OpenSSLName string `json:"openssl_name"`
	GnuTLSName  string `json:"gnutls_name"`
	Security    string `json:"security"`
}

type cipherSuiteResponse struct {
	CipherSuites []map[string]cipherSuite `json:"ciphersuites"`
}

func main() {
	var cipherfile string
	flag.StringVar(&cipherfile, "out-ciphers", "../../assets/cipherstatus_data.json", "File to write cipher stats")
	flag.Parse()

	ciphers, err := fetchAndLoadCiphers(cipherSuiteAPI)
	if err != nil || len(ciphers) < minExpectedCiphers {
		reason := fmt.Sprintf("got %d ciphers (want >= %d)", len(ciphers), minExpectedCiphers)
		if err != nil {
			reason = err.Error()
		}
		if skipOverwrite(cipherfile, reason) {
			return
		}
		gologger.Fatal().Msgf("refusing to write cipherstatus: %s (no usable existing dataset to keep)", reason)
	}

	bin, err := json.Marshal(ciphers)
	if err != nil {
		if skipOverwrite(cipherfile, err.Error()) {
			return
		}
		gologger.Fatal().Msgf("failed to marshal cipherstats %v", err)
	}
	if err := os.WriteFile(cipherfile, bin, 0600); err != nil {
		gologger.Fatal().Msgf("failed to write ciphers to file got %v", err)
	}
	gologger.Print().Msgf("updated cipherstatus.json, total unique ciphers : %v\n", len(ciphers))
}

// skipOverwrite leaves a filled dataset alone when the refresh failed or came
// back empty/truncated. Returns true when the existing file was kept.
func skipOverwrite(cipherfile, reason string) bool {
	existing, err := loadExistingCipherCount(cipherfile)
	if err != nil || existing < minExpectedCiphers {
		return false
	}
	gologger.Warning().Msgf("skipping cipherstatus overwrite (%s); keeping existing dataset with %d ciphers", reason, existing)
	return true
}

func loadExistingCipherCount(path string) (int, error) {
	bin, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var existing map[string]string
	if err := json.Unmarshal(bin, &existing); err != nil {
		return 0, err
	}
	return len(existing), nil
}

func fetchAndLoadCiphers(url string) (map[string]string, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	res, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			gologger.Warning().Msgf("Failed to close response body: %v", err)
		}
	}()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status code error: %d %s", res.StatusCode, res.Status)
	}
	return loadCiphersFromReader(res.Body)
}

func loadCiphersFromReader(r io.Reader) (map[string]string, error) {
	var response cipherSuiteResponse
	if err := json.NewDecoder(r).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode ciphersuites: %w", err)
	}
	return mapCiphersFromResponse(response), nil
}

func mapCiphersFromResponse(response cipherSuiteResponse) map[string]string {
	ciphers := make(map[string]string, len(response.CipherSuites)*3)
	for _, entry := range response.CipherSuites {
		for name, suite := range entry {
			level, ok := securityLevels[strings.ToLower(suite.Security)]
			if !ok {
				gologger.Warning().Msgf("skipping %v: unknown security level %q", name, suite.Security)
				continue
			}
			for _, alias := range []string{name, suite.OpenSSLName, suite.GnuTLSName} {
				if alias = strings.TrimSpace(alias); alias != "" {
					ciphers[strings.ToUpper(alias)] = level
				}
			}
		}
	}
	return ciphers
}
