package clients

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIsMisMatchedCert(t *testing.T) {
	type args struct {
		host  string   // actual host name
		names []string // cert names + alternate names
	}

	tests := []struct {
		args args
		want bool
	}{
		{args{host: "target.com", names: []string{"target.com"}}, false},
		{args{host: "target.com", names: []string{"other-target.com", "target.com"}}, false},
		{args{host: "subdomain.target.com", names: []string{"*.target.com", "other-target.com"}}, false},
		{args{host: "foo.example.net", names: []string{"*.example.net"}}, false},
		{args{host: "aaábçdë.ext", names: []string{"AaÁBçdë.ext"}}, false},

		{args{host: "baz1.example.net", names: []string{"baz*.example.net"}}, false},
		{args{host: "foobaz.example.net", names: []string{"*baz.example.net"}}, false},
		{args{host: "buzz.example.net", names: []string{"b*z.example.net"}}, false},

		// multilevel domains
		{args{host: "xyz.subdomain.target.com", names: []string{"*.target.com"}}, true},
		{args{host: "xyz.subdomain.target.com", names: []string{"*.subdomain.target.com"}}, false},

		// negative scenarios
		{args{host: "bar.foo.example.net", names: []string{"*.example.net"}}, true},
		{args{host: "target.com", names: []string{"other-target.com"}}, true},
		{args{host: "target.com", names: []string{"*-target.com"}}, true},
		{args{host: "target.com", names: []string{"target.*m"}}, true},

		{args{host: "*.target.com", names: []string{"other-target.com", "target.com", "subdomain.target.*"}}, true},
		{args{host: "*.com", names: []string{"other-target.com", "subdomain.target.com"}}, true},
		{args{host: "subdomain.target.com", names: []string{"other-target.com", "subdomain.target.*"}}, true},
		{args{host: "subdomain.target.com", names: []string{"subdomain.*.com", "other-target.com"}}, true},
	}

	for _, test := range tests {
		testName := fmt.Sprintf("(%s vs [%s])", test.args.host, strings.Join(test.args.names, ","))
		t.Run(testName, func(t *testing.T) {
			got := IsMisMatchedCert(test.args.host, test.args.names)
			assert.Equal(t, test.want, got)
		})
	}
}

func Test_matchWildCardToken(t *testing.T) {
	tests := []struct {
		nameToken string
		hostToken string
		want      bool
	}{
		{"b*z", "buzz", true},
		{"*buzz", "foobuzz", true},
		{"foo*", "foobuzz", true},
		{"*", "foo", true},
		{"subdomain", "subdomain", true},
		{"foo*", "buzz", false},
		{"*buzz", "foo", false},
	}
	for _, test := range tests {
		testName := fmt.Sprintf("'%s' -> '%s'", test.nameToken, test.hostToken)
		t.Run(testName, func(t *testing.T) {
			assert.Equal(t, test.want, matchWildCardToken(test.nameToken, test.hostToken))
		})
	}
}

func TestIsSelfSigned(t *testing.T) {
	tests := []struct {
		name          string
		authorityKeyID []byte
		subjectKeyID   []byte
		SANs          []string
		want          bool
	}{
		{
			name:          "Traditional self-signed: empty authority key ID",
			authorityKeyID: []byte{},
			subjectKeyID:   []byte{0x01, 0x02, 0x03},
			SANs:          []string{"example.com"},
			want:          true,
		},
		{
			name:          "Traditional self-signed: matching key IDs",
			authorityKeyID: []byte{0x01, 0x02, 0x03},
			subjectKeyID:   []byte{0x01, 0x02, 0x03},
			SANs:          []string{"example.com"},
			want:          true,
		},
		{
			name:          "Legitimate intermediate CA: different key IDs, no SANs",
			authorityKeyID: []byte{0x01, 0x02, 0x03},
			subjectKeyID:   []byte{0x04, 0x05, 0x06},
			SANs:          []string{},
			want:          false,
		},
		{
			name:          "Poorly generated self-signed: no authority key ID and no SANs",
			authorityKeyID: []byte{},
			subjectKeyID:   []byte{0x01, 0x02, 0x03},
			SANs:          []string{},
			want:          true,
		},
		{
			name:          "Normal certificate: different key IDs with SANs",
			authorityKeyID: []byte{0x01, 0x02, 0x03},
			subjectKeyID:   []byte{0x04, 0x05, 0x06},
			SANs:          []string{"example.com", "*.example.com"},
			want:          false,
		},
		{
			name:          "Normal certificate: different key IDs with single SAN",
			authorityKeyID: []byte{0x01, 0x02, 0x03},
			subjectKeyID:   []byte{0x04, 0x05, 0x06},
			SANs:          []string{"example.com"},
			want:          false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := IsSelfSigned(test.authorityKeyID, test.subjectKeyID, test.SANs)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestIsUntrustedCA(t *testing.T) {
	// Helper function to create a test certificate
	createTestCert := func(isCA bool, subjectKeyID, authorityKeyID []byte, dnsNames []string) *x509.Certificate {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		template := x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "Test Certificate",
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  isCA,
			SubjectKeyId:          subjectKeyID,
			AuthorityKeyId:        authorityKeyID,
			DNSNames:              dnsNames,
		}
		
		if isCA {
			template.KeyUsage |= x509.KeyUsageCertSign
		}
		
		certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
		cert, _ := x509.ParseCertificate(certDER)
		return cert
	}

	tests := []struct {
		name  string
		certs []*x509.Certificate
		want  bool
	}{
		{
			name: "Legitimate intermediate CA: different key IDs, no SANs",
			certs: []*x509.Certificate{
				createTestCert(true, []byte{0x04, 0x05, 0x06}, []byte{0x01, 0x02, 0x03}, []string{}),
			},
			want: false, // Should NOT be untrusted
		},
		{
			name: "Self-signed CA with empty authority key ID",
			certs: []*x509.Certificate{
				createTestCert(true, []byte{0x01, 0x02, 0x03}, []byte{}, []string{"example.com"}),
			},
			want: true, // Should be untrusted
		},
		{
			name: "Self-signed CA with matching key IDs",
			certs: []*x509.Certificate{
				createTestCert(true, []byte{0x01, 0x02, 0x03}, []byte{0x01, 0x02, 0x03}, []string{"example.com"}),
			},
			want: true, // Should be untrusted
		},
		{
			name: "Poorly generated self-signed CA: no authority key ID and no SANs",
			certs: []*x509.Certificate{
				createTestCert(true, []byte{0x01, 0x02, 0x03}, []byte{}, []string{}),
			},
			want: true, // Should be untrusted
		},
		{
			name: "End-entity certificate (not CA)",
			certs: []*x509.Certificate{
				createTestCert(false, []byte{0x01, 0x02, 0x03}, []byte{}, []string{"example.com"}),
			},
			want: false, // Should NOT be untrusted (not a CA)
		},
		{
			name: "Multiple certificates with legitimate intermediate CA",
			certs: []*x509.Certificate{
				createTestCert(false, []byte{0x07, 0x08, 0x09}, []byte{0x04, 0x05, 0x06}, []string{"example.com"}), // End-entity
				createTestCert(true, []byte{0x04, 0x05, 0x06}, []byte{0x01, 0x02, 0x03}, []string{}),                // Intermediate CA
			},
			want: false, // Should NOT be untrusted
		},
		{
			name: "Multiple certificates with self-signed CA",
			certs: []*x509.Certificate{
				createTestCert(false, []byte{0x07, 0x08, 0x09}, []byte{0x04, 0x05, 0x06}, []string{"example.com"}), // End-entity
				createTestCert(true, []byte{0x01, 0x02, 0x03}, []byte{0x01, 0x02, 0x03}, []string{}),                // Self-signed CA
			},
			want: true, // Should be untrusted
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := IsUntrustedCA(test.certs)
			assert.Equal(t, test.want, got)
		})
	}
}
