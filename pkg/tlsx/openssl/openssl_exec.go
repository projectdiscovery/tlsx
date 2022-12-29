package openssl

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
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
	newenv := "OPENSSL_CONF=" + OpenSSL_CONF
	cmd.Env = append(os.Environ(), newenv)
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
func readResponse(data string) (*Response, error) {
	response := &Response{}
	if !strings.Contains(data, "CONNECTED") {
		// If connected string is not available it
		// openssl failed completely and did not recover
		return nil, fmt.Errorf("openssl response does not contain 'CONNECTED' %v", data)
	}
	var err1, err2 error
	// openssl s_client returns lot of data however most of
	// it can be obtained from parse Certificate
	response.AllCerts, err1 = parseCertificates(data)
	// Parse Session Data
	response.Session, err2 = readSessionData(data)

	var err error
	switch {
	case err1 != nil:
		err = wraperrors(err, err1)
		fallthrough
	case err2 != nil:
		err = wraperrors(err, err2)
		fallthrough
	case response != nil && (response.AllCerts == nil || len(response.AllCerts) == 0):
		err = wraperrors(err, fmt.Errorf("no certificates found:\n%v", err))
		fallthrough
	case response != nil && response.Session == nil:
		err = wraperrors(err, fmt.Errorf("session is empty:\n%v", err))
		fallthrough
	case err != nil:
		// if any of above case is successful
		// add openssl response
		err = wraperrors(err, fmt.Errorf("\n%v", data))
	}
	return response, err
}

// read Session Data from openssl response
func readSessionData(data string) (*Session, error) {
	respreader := bufio.NewReader(strings.NewReader(data))
	inFlight := false
	osession := &Session{}

readline:
	line, err := respreader.ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, wraperrors(err, ErrNoSession)
	} else if err == io.EOF {
		return osession, nil
	}
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "SSL-Session") {
		inFlight = true
		goto readline
	}
	if inFlight {
		switch {
		case strings.HasPrefix(line, "Protocol"):
			osession.Protocol = parseSessionValue(line)
		case strings.HasPrefix(line, "Cipher"):
			osession.Cipher = parseSessionValue(line)
		case strings.HasPrefix(line, "Master-Key"):
			osession.MasterKey = parseSessionValue(line)
		}
		if !strings.HasPrefix(line, "Extended master secret") {
			// read until end of session data
			goto readline
		}
	} else {
		goto readline
	}
	return osession, nil
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
