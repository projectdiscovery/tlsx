package openssl

import (
	"strings"

	"github.com/projectdiscovery/gologger"
	errorutil "github.com/projectdiscovery/utils/errors" //nolint
)

// AllCipherNames contains all ciphers supported by openssl
var AllCiphersNames []string = []string{}

// cipherMap
var cipherMap map[string]struct{} = map[string]struct{}{}

// validate given ciphers and
func toOpenSSLCiphers(cipher ...string) ([]string, error) {
	arr := []string{}
	for _, v := range cipher {
		if _, ok := cipherMap[v]; ok {
			arr = append(arr, v)
		} else {
			return arr, errorutil.NewWithTag("openssl", "cipher suite %v not supported", v) //nolint
		}
	}
	return arr, nil
}

func parseSessionValue(line string) string {
	// use fields to avoid whitespace issues
	tarr := strings.Fields(line)
	if len(tarr) == 3 {
		return tarr[2]
	} else {
		return ""
	}
}

// Wraps err2 over err1 even if err is nil
func Wrap(err1 errorutil.Error, err2 errorutil.Error) errorutil.Error { //nolint
	if err1 == nil {
		return err2
	}
	return err1.Wrap(err2) //nolint
}

var certRequiredAlerts = []string{
	"SSL alert number 42",  // bad_certificate
	"SSL alert number 116", // certificate_required
}

// isClientCertRequired checks openssl output to see if the error is due to a client certificate being required by the server
func isClientCertRequired(data string) bool {
	for _, line := range strings.Split(data, "\n") {
		for _, alert := range certRequiredAlerts {
			if strings.Contains(line, alert) {
				return true
			}
		}
	}
	return false
}

func init() {
	if !IsAvailable() {
		return
	}
	ciphers, err := getCiphers()
	if err != nil {
		gologger.Debug().Label("openssl").Msg(err.Error())
	}
	for _, v := range ciphers {
		cipherMap[v] = struct{}{}
		AllCiphersNames = append(AllCiphersNames, v)
	}
}
