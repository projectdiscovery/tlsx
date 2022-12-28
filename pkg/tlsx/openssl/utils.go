package openssl

import (
	"strings"

	"github.com/projectdiscovery/gologger"
)

// AllCiphers
var AllCiphers map[string]struct{} = map[string]struct{}{}

// returns array of openssl Ciphers
func fetchCiphers() []string {
	arr := []string{}
	for k := range AllCiphers {
		arr = append(arr, k)
	}
	return arr
}

// validate given ciphers and
func validateCiphers(cipher ...string) []string {
	arr := []string{}
	for _, v := range cipher {
		if _, ok := AllCiphers[v]; ok {
			arr = append(arr, v)
		} else {
			gologger.Debug().Label("openssl").Msgf("does not support %v cipher. skipping..", v)
		}
	}
	return arr
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

func init() {
	if !IsAvailable() {
		return
	}
	ciphers, err := getCiphers()
	if err != nil {
		gologger.Debug().Label("openssl").Msg(err.Error())
	}
	for _, v := range ciphers {
		AllCiphers[v] = struct{}{}
	}
}
