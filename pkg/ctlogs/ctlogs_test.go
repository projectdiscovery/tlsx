package ctlogs

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatSourceID(t *testing.T) {
	service := &CTLogsService{}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Google log with quotes",
			input:    "Google 'Xenon2025h2'",
			expected: "google_xenon2025h2",
		},
		{
			name:     "Sectigo log with quotes",
			input:    "Sectigo 'Sabre2025h2'",
			expected: "sectigo_sabre2025h2",
		},
		{
			name:     "DigiCert log with spaces",
			input:    "DigiCert Log2025h1",
			expected: "digicert_log2025h1",
		},
		{
			name:     "Cloudflare log with hyphens",
			input:    "Cloudflare-Nimbus2026",
			expected: "cloudflare_nimbus2026",
		},
		{
			name:     "Simple name",
			input:    "TestLog",
			expected: "testlog",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.formatSourceID(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCertificateToResponse(t *testing.T) {
	// Create a test certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(123456789),
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		Issuer: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test CA Org"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              []string{"test.example.com", "*.test.example.com"},
		AuthorityKeyId:        []byte{1, 2, 3, 4},
		SubjectKeyId:          []byte{1, 2, 3, 4}, // Same as AuthorityKeyId for self-signed
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	svcOpts := ServiceOptions{Verbose: false, Cert: false}
	service := &CTLogsService{options: svcOpts}

	response := ConvertCertificateToResponse(cert, "Test Log Source", service.options.Cert)

	require.NotNil(t, response)
	assert.Equal(t, "test.example.com", response.Host)
	assert.Equal(t, "443", response.Port)
	assert.True(t, response.ProbeStatus)
	assert.Equal(t, "test_log_source", response.CTLogSource)
	assert.NotNil(t, response.CertificateResponse)

	certResp := response.CertificateResponse
	assert.Equal(t, "test.example.com", certResp.SubjectCN)
	assert.Equal(t, "Test CA", certResp.IssuerCN)
	assert.Equal(t, []string{"Test Org"}, certResp.SubjectOrg)
	assert.Equal(t, []string{"Test CA Org"}, certResp.IssuerOrg)
	assert.Equal(t, []string{"test.example.com", "*.test.example.com"}, certResp.SubjectAN)
	assert.True(t, certResp.SelfSigned)   // Should be true since AuthorityKeyId == SubjectKeyId
	assert.True(t, certResp.WildCardCert) // Should be true due to *.test.example.com
	assert.False(t, certResp.Expired)
}

func TestCertificateToResponseWithEmptyHost(t *testing.T) {
	// Create a certificate without hostname
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(123456789),
		Subject: pkix.Name{
			CommonName: "", // Empty CN
		},
		Issuer: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		DNSNames:  []string{}, // Empty DNS names
	}

	svcOpts := ServiceOptions{Verbose: false, Cert: false}
	service := &CTLogsService{options: svcOpts}

	response := ConvertCertificateToResponse(cert, "Test Log Source", service.options.Cert)

	// Should return nil for certificates without hostname
	assert.Nil(t, response)
}

func TestCertificateToResponseWithCertOption(t *testing.T) {
	// Create a test certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(123456789),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		Issuer: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		DNSNames:  []string{"test.example.com"},
	}

	svcOpts := ServiceOptions{Verbose: false, Cert: true}
	service := &CTLogsService{options: svcOpts}

	response := ConvertCertificateToResponse(cert, "Test Log Source", service.options.Cert)

	require.NotNil(t, response)
	assert.NotEmpty(t, response.Certificate)

	// Verify the certificate is in PEM format
	block, _ := pem.Decode([]byte(response.Certificate))
	assert.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)
}

func TestCTLogsServiceInitialization(t *testing.T) {

	// This test will fail if the CT log list is unreachable
	// In a real test environment, you might want to mock the HTTP client
	service, err := New(
		WithVerbose(false),
		WithCert(false),
	)

	// We expect this to either succeed or fail due to network issues
	// The important thing is that it doesn't panic
	if err != nil {
		t.Logf("CT logs service initialization failed (expected in test environment): %v", err)
		return
	}

	require.NotNil(t, service)
	assert.NotNil(t, service.options)
	assert.NotNil(t, service.ctx)
	assert.NotNil(t, service.cancel)
}

func TestCTLogsServiceContextCancellation(t *testing.T) {
	service, err := New(
		WithVerbose(false),
		WithCert(false),
	)
	if err != nil {
		t.Skipf("Skipping test due to initialization failure: %v", err)
	}

	// Test context cancellation
	service.cancel()

	// Wait a bit for goroutines to clean up
	time.Sleep(100 * time.Millisecond)

	// The context should be cancelled
	select {
	case <-service.ctx.Done():
		// Expected
	default:
		t.Error("Context should be cancelled")
	}
}

func TestCertificateResponseFields(t *testing.T) {
	// Test that all critical certificate fields are properly set
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(123456789),
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		Issuer: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test CA Org"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              []string{"test.example.com", "*.test.example.com"},
		AuthorityKeyId:        []byte{1, 2, 3, 4},
		SubjectKeyId:          []byte{5, 6, 7, 8}, // Different from AuthorityKeyId
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	svcOpts := ServiceOptions{Verbose: false, Cert: false}
	service := &CTLogsService{options: svcOpts}

	response := ConvertCertificateToResponse(cert, "Test Log Source", service.options.Cert)

	require.NotNil(t, response)
	certResp := response.CertificateResponse

	// Test all critical fields
	assert.Equal(t, "test.example.com", certResp.SubjectCN)
	assert.Equal(t, "Test CA", certResp.IssuerCN)
	assert.Equal(t, []string{"Test Org"}, certResp.SubjectOrg)
	assert.Equal(t, []string{"Test CA Org"}, certResp.IssuerOrg)
	assert.Equal(t, []string{"test.example.com", "*.test.example.com"}, certResp.SubjectAN)
	assert.False(t, certResp.SelfSigned)  // Should be false since AuthorityKeyId != SubjectKeyId
	assert.True(t, certResp.WildCardCert) // Should be true due to *.test.example.com
	assert.False(t, certResp.Expired)
	assert.NotEmpty(t, certResp.Serial)
	assert.NotEmpty(t, certResp.SubjectDN)
	assert.NotEmpty(t, certResp.IssuerDN)
	assert.NotEmpty(t, certResp.FingerprintHash.MD5)
	assert.NotEmpty(t, certResp.FingerprintHash.SHA1)
	assert.NotEmpty(t, certResp.FingerprintHash.SHA256)
}
