package main

import (
	"encoding/json"
	"flag"
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

// stores ciphers with stats ex: "AES128-SHA256": "Weak"
var ciphers map[string]string = map[string]string{}

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

	FetchAndLoadCiphers(cipherSuiteAPI)

	if len(ciphers) < minExpectedCiphers {
		gologger.Fatal().Msgf("refusing to write cipherstatus: got %v ciphers, expected at least %v", len(ciphers), minExpectedCiphers)
	}

	bin, err := json.Marshal(ciphers)
	if err != nil {
		gologger.Fatal().Msgf("failed to marshal cipherstats %v", err)
	}
	err = os.WriteFile(cipherfile, bin, 0600)
	if err != nil {
		gologger.Fatal().Msgf("failed to write ciphers to file got %v", err)
	}
	gologger.Print().Msgf("updated cipherstatus.json, total unique ciphers : %v\n", len(ciphers))
}

func FetchAndLoadCiphers(url string) {
	client := &http.Client{Timeout: 60 * time.Second}
	res, err := client.Get(url)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			gologger.Warning().Msgf("Failed to close response body: %v", err)
		}
	}()
	if res.StatusCode != http.StatusOK {
		gologger.Fatal().Msgf("status code error: %d %s", res.StatusCode, res.Status)
	}

	var response cipherSuiteResponse
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		gologger.Fatal().Msgf("failed to decode ciphersuites got %v", err)
	}

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
}
