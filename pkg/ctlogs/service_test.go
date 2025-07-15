package ctlogs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	x509ct "github.com/google/certificate-transparency-go/x509"
	boom "github.com/tylertreat/BoomFilters"
)

func TestDedupAndStats(t *testing.T) {
	svcOpts := ServiceOptions{}
	svcOpts.PollInterval = 0

	svc := &CTLogsService{options: svcOpts, deduper: boom.NewInverseBloomFilter(100)}

	// create dummy CTLogSource
	svc.sources = []*CTLogSource{}

	der := generateCertDER(t, "example.com")
	ctCert, err := x509ct.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse google cert: %v", err)
	}
	entry := ct.LogEntry{X509Cert: ctCert}
	source := &CTLogSource{Client: &CTLogClient{}}

	// first insert unique
	_ = svc.processEntry(source, &entry, 1)
	// duplicate
	_ = svc.processEntry(source, &entry, 2)

	stats := svc.GetStats()
	if stats.Total != 2 || stats.Unique != 1 || stats.Duplicates != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func generateCertDER(t *testing.T, cn string) []byte {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key gen error: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("cert create: %v", err)
	}
	return der
}
