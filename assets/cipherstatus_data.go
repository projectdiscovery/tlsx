package assets

import (
	_ "embed"
	"encoding/json"

	"github.com/projectdiscovery/gologger"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

//go:embed cipherstatus_data.json
var CipherDataBin string

// CipherSecLevel contains cipher and its security level
// Source:  https://ciphersuite.info/
var CipherSecLevel map[string]string = map[string]string{}

// GetSecureCiphers returns Ciphers with status `Recommended` and `Secure`
// Ex: https://ciphersuite.info/cs/TLS_AES_128_CCM_8_SHA256/
func GetSecureCipherSuites() []string {
	return getCipherWithLevel("Recommended", "Secure")
}

// GetInSecureCipherSuites returns Ciphers with status `Insecure`.
// Insecure Ciphers either uses no authentication at all or does not provide confidentiality
// Ex: https://ciphersuite.info/cs/TLS_NULL_WITH_NULL_NULL/
func GetInSecureCipherSuites() []string {
	return getCipherWithLevel("Insecure")
}

// GetWeakCipherSuites returns Ciphers with status `Weak`.
// Weak Cipher suites use algorithms that are proven to be weak or can be broken
// Ex: https://ciphersuite.info/cs/TLS_RSA_WITH_AES_256_CBC_SHA/
func GetWeakCipherSuites() []string {
	return getCipherWithLevel("Weak")
}

// returns cipher with level
func getCipherWithLevel(level ...string) []string {
	arr := []string{}
	for k, v := range CipherSecLevel {
		if stringsutil.EqualFoldAny(v, level...) {
			arr = append(arr, k)
		}
	}
	return arr
}

func init() {
	err := json.Unmarshal([]byte(CipherDataBin), &CipherSecLevel)
	if err != nil {
		gologger.Error().Label("cipher").Msgf("failed to load cipherstatus_data.json, cipher-enum might return unexpected results: %v", err)
	}
}
