package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/projectdiscovery/gologger"
)

// references:
// - https://ccadb.my.salesforce-sites.com/mozilla/CACertificatesInFirefoxReport
// - https://curl.se/docs/caextract.html
var rootCertURL = "https://curl.se/ca/cacert.pem"

func main() {
	var rootCertFile string
	flag.StringVar(&rootCertFile, "out-root-certs", "../../assets/root-certs.pem", "File to root certs data (PEM format)")
	flag.Parse()

	rootCertData, err := fetchRootCerts(rootCertURL)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}
	if err = os.WriteFile(rootCertFile, rootCertData, 0644); err != nil {
		gologger.Fatal().Msg(err.Error())
	}
	parsedRootCerts, err := parseCertificates(rootCertData)
	if err != nil {
		gologger.Fatal().Msgf("failed to parse root certs: %v", err)
	}
	gologger.Print().Msgf("updated root-certs.pem, total root certs : %v\n", len(parsedRootCerts))
}

func fetchRootCerts(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("could not fetch root certs")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status code error: %d %s", resp.StatusCode, resp.Status)
	}
	certs, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read root certs: %v", err)
	}
	return certs, nil
}

func parseCertificates(data []byte) ([]*x509.Certificate, error) {
	var parsedCerts []*x509.Certificate
	var err error
	block, rest := pem.Decode(data)
	for block != nil {
		if block.Type == "CERTIFICATE" {
			cert, errx := x509.ParseCertificate(block.Bytes)
			if errx != nil {
				err = fmt.Errorf("could not parse certificate: %s", errx.Error())
				continue
			}
			parsedCerts = append(parsedCerts, cert)
		}
		if len(rest) == 0 {
			break
		}
		block, rest = pem.Decode(rest)
	}
	return parsedCerts, err
}
