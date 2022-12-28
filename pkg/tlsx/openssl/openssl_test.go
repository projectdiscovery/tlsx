package openssl

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"strings"
	"testing"
)

func TestGetCipherSuites(t *testing.T) {
	var ciphers []string
	var err error
	if ciphers, err = getCiphers(); err != nil {
		t.Errorf(err.Error())
	}
	if len(ciphers) < 5 {
		t.Errorf("Failed to get cipher suites got\n%v", ciphers)
	}
}

func TestResponse(t *testing.T) {
	testcases := []struct {
		Command     string
		ErrContains string // errors returned by openssl
		cert        *x509.Certificate
	}{
		// {"s_client -connect projectdiscovery.io:443 -tls1", "handshake failure", nil},
		{"s_client -connect scanme.sh:443", "", &x509.Certificate{Issuer: pkix.Name{Organization: []string{"pd"}, CommonName: "scanme"}}},
	}

	for _, v := range testcases {
		bin, errstring, err := execOpenSSL(context.Background(), strings.Fields(v.Command))
		if err != nil {
			t.Errorf("failed to execute cmd:%v\ngot error %v", v.Command, err)
		}
		if v.ErrContains != "" && !strings.Contains(errstring, v.ErrContains) {
			t.Errorf("openssl: expected %v but got %v", v.ErrContains, errstring)
		}
		if v.cert != nil {
			ocert, err := parseCertificates(bin)
			if err != nil {
				t.Errorf(err.Error())
			}
			if ocert[0].Issuer.CommonName != v.cert.Issuer.CommonName {
				t.Errorf("expected %v but got %v", v.cert.Issuer.CommonName, ocert[0].Issuer.CommonName)
			}
		}
	}
}

func TestCertChain(t *testing.T) {
	opts := Options{
		Address:   "projectdiscovery.io:443",
		CertChain: true,
	}

	args, err := opts.Args()
	if err != nil {
		t.Errorf(err.Error())
	}

	bin, _, err := execOpenSSL(context.Background(), args)
	if err != nil {
		t.Errorf("failed to execute cmd:%v\ngot error %v", args, err)
	}

	xchain, err := parseCertificates(bin)
	if err != nil {
		t.Errorf("failed to parse certChain: %v", err.Error())
	}
	if len(xchain) < 2 {
		t.Errorf("certChain: expected at least 2 certs but got %v", len(xchain))
	}
}

func TestSessionData(t *testing.T) {
	opts := Options{
		Address: "scanme.sh:443",
	}
	versions := []string{"tls10", "tls11", "tls12", "tls13"}
	for _, v := range versions {
		opts.Protocol = getProtocol(v)
		args, err := opts.Args()
		if err != nil {
			t.Errorf("failed to create cmd: %v", err)
		}
		out, _, err := execOpenSSL(context.TODO(), args)
		if err != nil {
			t.Errorf("failed to create cmd: %v", err)
		}
		resp, err := readResponse(out)
		if err != nil {
			t.Errorf("failed to create cmd: %v", err)
		}
		if resp.Session.getTLSVersion() != v {
			t.Errorf("expected tlsversion %v but got %v", v, resp.Session.getTLSVersion())
		}
	}
}

func TestMain(m *testing.M) {
	if !IsAvailable() {
		log.Print(ErrNotAvailable)
	} else {
		m.Run()
	}
}
