package openssl

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// execute openssl command and get results
func execOpenSSL(ctx context.Context, args []string) (string, string, error) {
	/*
		after executing given command it returns
		1. Stdout stream of OpenSSL which contains certificate and actual response
		2. Stderr which contains errors detected by openssl
		   i) Ex: Self Signed Certificate etc
		   ii) or other warnings
		3. error purely realted to I/O and command execution
	*/
	var outbuff, inbuff, errbuff bytes.Buffer
	cmd := exec.CommandContext(ctx, BinaryPath)
	cmd.Args = args
	cmd.Stderr = &errbuff
	cmd.Stdout = &outbuff
	cmd.Stdin = &inbuff
	inbuff.WriteString("Q")

	if err := cmd.Start(); err != nil {
		return outbuff.String(), errbuff.String(), fmt.Errorf("failed to start openssl: %v", err)
	}
	if err := cmd.Wait(); err != nil && errbuff.Len() == 0 {
		return outbuff.String(), errbuff.String(), err
	}
	return strings.TrimSpace(outbuff.String()), errbuff.String(), nil
}

// getCiphers returns openssl ciphers
func getCiphers() ([]string, error) {
	ciphers := []string{}
	res, _, err := execOpenSSL(context.TODO(), []string{"ciphers"})
	if err != nil {
		return ciphers, err
	}
	res = strings.TrimSpace(res)
	ciphers = append(ciphers, strings.Split(res, ":")...)
	return ciphers, nil
}

// read openssl s_client response
func readResponse(data string) ([]*x509.Certificate, error) {
	if !strings.Contains(data, "CONNECTED") {
		// If connected string is not available it
		// openssl failed completely and did not recover
		return nil, fmt.Errorf(data)
	}

	// openssl s_client returns lot of data however most of
	// it can be obtained from parse Certificate
	return parseCertificates(data)
}

// parseCertificate dumped by openssl
func parseCertificates(data string) ([]*x509.Certificate, error) {
	var certBuff bytes.Buffer
	certArr := []*x509.Certificate{}
	certReader := bufio.NewReader(strings.NewReader(data))
	inFlight := false

readline:
	line, err := certReader.ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, ErrCertParse
	} else if err == io.EOF {
		return certArr, nil
	}
	line = strings.TrimSpace(line)
	if line == "-----BEGIN CERTIFICATE-----" {
		certBuff.WriteString(line)
		certBuff.WriteString("\n")
		inFlight = true
	} else if line == "-----END CERTIFICATE-----" && inFlight {
		certBuff.WriteString(line)
		certBuff.WriteString("\n")
		inFlight = false
		xcert, er := getx509Certificate(certBuff.Bytes())
		if er != nil {
			return nil, er
		}
		certArr = append(certArr, xcert)
		certBuff.Reset()
	} else if inFlight {
		certBuff.WriteString(line)
		certBuff.WriteString("\n")
	}
	goto readline // read until buffer is empty
}

func getx509Certificate(certBin []byte) (*x509.Certificate, error) {
	if len(certBin) == 0 {
		return nil, fmt.Errorf("cert is empty: %v", ErrCertParse)
	}

	block, _ := pem.Decode(certBin)
	if block == nil {
		return nil, fmt.Errorf("not a valid pem")
	}
	crt, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		return nil, fmt.Errorf("parsex509: %v", e)
	}
	return crt, nil
}
