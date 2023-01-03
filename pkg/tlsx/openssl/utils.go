package openssl

import (
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/utils/errors"
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

// Wraps err2 over err1 even if err is nil
func Wrap(err1 errors.Error, err2 errors.Error) errors.Error {
	if err1 == nil {
		return err2
	}
	return err1.Wrap(err2)
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
