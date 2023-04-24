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

	errorutils "github.com/projectdiscovery/utils/errors"
)

const commadFormat string = "Command: %v"

type CMDOUT struct {
	Command string
	Stdout  string
	Stderr  string
}

// execute openssl command and get results
func execOpenSSL(ctx context.Context, args []string) (*CMDOUT, error) {
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
	if !IsLibreSSL {
		newenv := "OPENSSL_CONF=" + OPENSSL_CONF
		cmd.Env = append(os.Environ(), newenv)
	}
	cmd.Args = args
	cmd.Stderr = &errbuff
	cmd.Stdout = &outbuff
	cmd.Stdin = &inbuff
	inbuff.WriteString("Q")

	cmdstring := BinaryPath + " " + strings.Join(args, " ")
	if err := cmd.Start(); err != nil {
		return &CMDOUT{Command: cmdstring, Stderr: errbuff.String(), Stdout: outbuff.String()}, fmt.Errorf("failed to start openssl: %v", err)
	}
	if err := cmd.Wait(); err != nil && errbuff.Len() == 0 {
		return &CMDOUT{Command: cmdstring, Stderr: errbuff.String(), Stdout: outbuff.String()}, err
	}
	return &CMDOUT{Command: cmdstring, Stderr: errbuff.String(), Stdout: outbuff.String()}, nil
}

// getCiphers returns openssl ciphers
func getCiphers() ([]string, error) {
	ciphers := []string{}
	res, err := execOpenSSL(context.TODO(), []string{"ciphers"})
	if err != nil {
		return ciphers, err
	}
	out := strings.TrimSpace(res.Stdout)
	ciphers = append(ciphers, strings.Split(out, ":")...)
	return ciphers, nil
}

// read openssl s_client response
func getResponse(ctx context.Context, opts *Options) (*Response, errorutils.Error) {
	args, errx := opts.Args()
	if errx != nil {
		return nil, errorutils.NewWithErr(errx).WithTag(PkgTag).Msgf("failed to create cmd from args got %v", *opts)
	}
	result, err := execOpenSSL(ctx, args)
	if err != nil {
		return nil, errorutils.NewWithErr(err).WithTag(PkgTag, BinaryPath).Msgf("failed to execute openssl got %v", result.Stderr).Msgf(commadFormat, result.Command)
	}
	response := &Response{}
	if !strings.Contains(result.Stdout, "CONNECTED") {
		// If connected string is not available it
		// openssl failed completely and did not recover
		return nil, errorutils.NewWithTag(PkgTag, "failed to parse 'CONNECTED' not found got %v", result.Stderr).Msgf(commadFormat, result.Command)
	}
	var errParseCertificates, errParseSessionData error
	// openssl s_client returns lot of data however most of
	// it can be obtained from parse Certificate
	if !opts.SkipCertParse {
		response.AllCerts, errParseCertificates = parseCertificates(result.Stdout)
	}
	// Parse Session Data
	response.Session, errParseSessionData = readSessionData(result.Stdout)

	var allerrors errorutils.Error
	if errParseCertificates != nil {
		allerrors = Wrap(allerrors, errorutils.NewWithErr(errParseCertificates).WithTag(PkgTag).Msgf("failed to parse server certificate from response"))
	}
	if errParseSessionData != nil {
		allerrors = Wrap(allerrors, errorutils.NewWithErr(errParseSessionData).WithTag(PkgTag).Msgf("failed to parse session data from response"))
	}
	if !opts.SkipCertParse && len(response.AllCerts) == 0 {
		allerrors = Wrap(allerrors, errorutils.NewWithTag(PkgTag, "no server certificates found"))
	}
	if allerrors != nil {
		// if any of above case is successful
		// add openssl response
		return nil, allerrors.Msgf("failed to parse openssl response. original response is:\n%v", *result).Msgf(commadFormat, result.Command)
	}
	return response, nil
}

// read Session Data from openssl response
func readSessionData(data string) (*Session, error) {
	respreader := bufio.NewReader(strings.NewReader(data))
	inFlight := false
	osession := &Session{}

readline:
	line, err := respreader.ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, errorutils.NewWithErr(err).WithTag(PkgTag).Wrap(ErrNoSession)
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
		if strings.HasPrefix(line, "Timeout") {
			// read until end of session data and return
			return osession, nil
		}
	}
	goto readline
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
		xcert, certerr := getx509Certificate(certBuff.Bytes())
		if certerr != nil {
			return nil, errorutils.NewWithErr(certerr).WithTag(PkgTag).Msgf("failed to parse x509 certificate from PEM data of openssl")
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
