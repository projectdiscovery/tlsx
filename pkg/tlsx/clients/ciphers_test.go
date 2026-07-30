package clients

import (
	"testing"

	"github.com/projectdiscovery/tlsx/assets"
	"github.com/stretchr/testify/require"
)

func TestEmbeddedCipherStatusDatasetPopulated(t *testing.T) {
	t.Parallel()

	require.GreaterOrEqual(t, len(assets.CipherSecLevel), 300,
		"embedded cipherstatus dataset must not be empty/truncated")

	allowed := map[string]struct{}{
		"Recommended": {},
		"Secure":      {},
		"Weak":        {},
		"Insecure":    {},
	}
	for name, level := range assets.CipherSecLevel {
		if _, ok := allowed[level]; !ok {
			t.Fatalf("unexpected security level %q for %s", level, name)
		}
	}
}

func TestGetCipherLevelIANAAndOpenSSLAliases(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		level CipherSecLevel
	}{
		// IANA names
		{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", Secure},
		{"TLS_AES_128_GCM_SHA256", Secure}, // Recommended maps to Secure
		{"TLS_RSA_WITH_RC4_128_MD5", Insecure},
		{"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", Weak},
		// OpenSSL aliases from the same dataset
		{"ECDHE-RSA-AES128-GCM-SHA256", Secure},
		{"ECDHE-ECDSA-AES128-GCM-SHA256", Secure},
		{"ADH-AES128-GCM-SHA256", Insecure},
		{"ECDHE-RSA-DES-CBC3-SHA", Weak},
		// case-insensitive match
		{"tls_ecdhe_rsa_with_aes_128_gcm_sha256", Secure},
		{"ecdhe-rsa-aes128-gcm-sha256", Secure},
		// unknown
		{"TLS_NOT_A_REAL_CIPHER_SUITE", Unknown},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.level, GetCipherLevel(tc.name))
		})
	}
}

func TestGetCiphersWithLevelFiltersAliases(t *testing.T) {
	t.Parallel()

	list := []string{
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"ECDHE-RSA-AES128-GCM-SHA256",
		"ADH-AES128-GCM-SHA256",
		"TLS_NOT_A_REAL_CIPHER_SUITE",
	}

	secure := GetCiphersWithLevel(list, Secure)
	require.ElementsMatch(t, []string{
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"ECDHE-RSA-AES128-GCM-SHA256",
	}, secure)

	insecure := GetCiphersWithLevel(list, Insecure)
	require.Equal(t, []string{"ADH-AES128-GCM-SHA256"}, insecure)
}
