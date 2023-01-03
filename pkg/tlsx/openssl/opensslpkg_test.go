package openssl_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/openssl"
)

func TestOpenssL(t *testing.T) {
	client, err := openssl.New(&clients.Options{
		Timeout:  6,
		Verbose:  true,
		TLSChain: true,
	})
	if err != nil && !errors.Is(err, openssl.ErrNotAvailable) {
		t.Fatalf("unkown error: %v", err)
	}

	versions, err := client.SupportedTLSVersions()
	if err != nil || versions == nil || len(versions) == 0 {
		t.Fatalf("failed to get openssl tls versions: %v %v", versions, err)
	}

	// fetched using openssl command
	ciphers, err := client.SupportedTLSCiphers()
	if err != nil || ciphers == nil || len(ciphers) == 0 {
		t.Fatalf("failed to fetch openssl ciphers: %v %v", err, ciphers)
	}
	fd, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
	if err != nil || fd == nil {
		t.Fatalf("failed to dial : %v", err)
	}
	dnsData, err := fd.GetDNSData("scanme.sh")
	if err != nil || dnsData == nil {
		t.Fatalf("failed to fetch dnsdata : %v", err)
	}

	resp, err := client.ConnectWithOptions("scanme.sh", "", "443", clients.ConnectOptions{
		VersionTLS: "tls11",
		SNI:        "scanme.sh",
	})
	if err != nil || resp == nil {
		t.Errorf("failed to connect using openssl: %v", err)
	}
	if resp.Version != "tls11" {
		t.Errorf("something went wrong expected version %v but got %v", "tls11", resp.Version)
	}

	if len(resp.Chain) == 0 || resp.Chain[0] == nil {
		// cert chain length should at least be one(if self signed)
		t.Errorf("invalid cert chain : %v", *resp)
	} else {
		cert := resp.Chain[0]
		org := []string{"pd"}
		if cert.IssuerCN != "scanme" || cert.SubjectCN != "scanme" || !reflect.DeepEqual(cert.IssuerOrg, org) || !reflect.DeepEqual(cert.SubjectOrg, org) {
			t.Errorf("malformed response parsed from certificate got issuer: %v %v,subject %v %v", cert.IssuerCN, cert.IssuerOrg, cert.SubjectCN, cert.SubjectOrg)
		}
	}

	for _, v := range dnsData.A {
		// Try connecting using IP
		resp2, err := client.ConnectWithOptions("scanme.sh", v, "443", clients.ConnectOptions{
			VersionTLS: "tls12",
		})
		if err != nil {
			t.Errorf("failed to connect using openssl: %v", err)
		}
		if resp2.Version != "tls12" {
			t.Errorf("something went wrong expected version %v but got %v", "tls12", resp2.Version)
		}
		if resp2.IssuerCN != "scanme" {
			t.Errorf("invalid certificate parsed cert is %v", resp2.Certificate)
		}
	}
}
