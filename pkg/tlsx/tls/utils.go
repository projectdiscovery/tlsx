package tls

import (
	"crypto/tls"
	"slices"
	"strings"

	"github.com/projectdiscovery/utils/errkit"
	errorutil "github.com/projectdiscovery/utils/errors" //nolint
)

var (
	AllCiphers           []uint16
	AllCiphersNames      []string
	SupportedTlsVersions []string
)

func init() {
	for name, cipher := range tlsCiphers {
		AllCiphersNames = append(AllCiphersNames, name)
		AllCiphers = append(AllCiphers, cipher)
	}
	for name := range versionStringToTLSVersion {
		SupportedTlsVersions = append(SupportedTlsVersions, name)
	}
}

// SupportedTLSGroups is the list of key exchange group names accepted by toTLSGroups
var SupportedTLSGroups = []string{"X25519MLKEM768", "X25519", "CurveP256", "CurveP384", "CurveP521"}

// toTLSGroups converts key exchange group names (matched case-insensitively)
// to curve IDs, also returning the canonical group names.
func toTLSGroups(items []string) ([]tls.CurveID, []string, error) {
	var (
		groups []tls.CurveID
		names  []string
	)
	for _, item := range items {
		var group tls.CurveID
		for _, name := range SupportedTLSGroups {
			if strings.EqualFold(item, name) {
				group = tlsGroups[name]
				break
			}
		}
		if group == 0 {
			return nil, nil, errkit.Newf("tls group %v not supported (supported: %v)", item, strings.Join(SupportedTLSGroups, ","))
		}
		if slices.Contains(groups, group) {
			return nil, nil, errkit.Newf("tls group %v specified more than once", item)
		}
		groups = append(groups, group)
		names = append(names, group.String())
	}
	return groups, names, nil
}

var tlsGroups = map[string]tls.CurveID{
	"X25519MLKEM768": tls.X25519MLKEM768,
	"X25519":         tls.X25519,
	"CurveP256":      tls.CurveP256,
	"CurveP384":      tls.CurveP384,
	"CurveP521":      tls.CurveP521,
}

func toTLSCiphers(items []string) ([]uint16, error) {
	var convertedCiphers []uint16
	for _, item := range items {
		cipher, ok := tlsCiphers[item]
		if !ok {
			return nil, errorutil.NewWithTag("ctls", "cipher suite %v not supported", item) //nolint
		}
		convertedCiphers = append(convertedCiphers, cipher)
	}
	return convertedCiphers, nil
}

var tlsCiphers = map[string]uint16{
	"TLS_RSA_WITH_RC4_128_SHA":                      tls.TLS_RSA_WITH_RC4_128_SHA,
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":                 tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	"TLS_RSA_WITH_AES_128_CBC_SHA":                  tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"TLS_RSA_WITH_AES_256_CBC_SHA":                  tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	"TLS_RSA_WITH_AES_128_CBC_SHA256":               tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	"TLS_RSA_WITH_AES_128_GCM_SHA256":               tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_RSA_WITH_AES_256_GCM_SHA384":               tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":              tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":          tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":          tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_RC4_128_SHA":                tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":           tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":            tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":            tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":       tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":         tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":         tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":       tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":         tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":       tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	"TLS_AES_128_GCM_SHA256":                        tls.TLS_AES_128_GCM_SHA256,
	"TLS_AES_256_GCM_SHA384":                        tls.TLS_AES_256_GCM_SHA384,
	"TLS_CHACHA20_POLY1305_SHA256":                  tls.TLS_CHACHA20_POLY1305_SHA256,
	"TLS_FALLBACK_SCSV":                             tls.TLS_FALLBACK_SCSV,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":          tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":        tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
}
