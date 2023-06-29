package clients

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	iputil "github.com/projectdiscovery/utils/ip"
)

var rootCerts []*x509.Certificate

func init() {
	var rootCertFile, deafultRootCertFile string
	deafultRootCertFile = "root-certs.pem"
	rootCertFile = os.Getenv("SSL_CERT_FILE")
	if rootCertFile != "" {
		if !fileutil.FileExists(rootCertFile) {
			gologger.Warning().Msgf("file %s does not exist", rootCertFile)
			return
		}
		data, err := os.ReadFile(rootCertFile)
		if err != nil {
			gologger.Warning().Label("SSL_CERT_FILE").Msg(err.Error())
			return
		}
		if rootCerts, err = parseCertificates(data); err != nil {
			gologger.Warning().Msg(err.Error())
		}
		return
	}

	if !fileutil.FileExists(deafultRootCertFile) {
		if _, err := os.Create(deafultRootCertFile); err != nil {
			gologger.Warning().Label("Root Cert").Msg(err.Error())
		}
	}
	oldCerts, err := os.ReadFile(deafultRootCertFile)
	if err != nil {
		gologger.Warning().Msg("could not read default root cert file")
		return
	}
	newCerts, err := fetchRootCerts()
	if err != nil {
		gologger.Warning().Msg(err.Error())
		if len(oldCerts) == 0 {
			return
		}
		newCerts = oldCerts
	}
	// check root certifcates are changed at https://curl.se/docs/caextract.html
	if len(newCerts) != len(oldCerts) {
		if err := os.WriteFile(deafultRootCertFile, newCerts, 0644); err != nil {
			gologger.Warning().Msg(err.Error())
			return
		}
	}
	if rootCerts, err = parseCertificates(newCerts); err != nil {
		gologger.Warning().Msg(err.Error())
	}
}

func fetchRootCerts() ([]byte, error) {
	// references:
	// - https://ccadb.my.salesforce-sites.com/mozilla/CACertificatesInFirefoxReport
	// - https://curl.se/docs/caextract.html
	resp, err := http.Get("https://curl.se/ca/cacert.pem")
	if err != nil {
		return nil, errorutil.New("could not fetch root certs").Wrap(err)
	}
	defer resp.Body.Close()
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
				err = errorutil.New("could not parse certificate").Wrap(errx)
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

func IsRootCert(cert *x509.Certificate) bool {
	for _, c := range rootCerts {
		if bytes.Equal(c.Raw, cert.Raw) {
			return true
		}
	}
	return false
}

func Convertx509toResponse(options *Options, hostname string, cert *x509.Certificate, showcert bool) *CertificateResponse {
	response := &CertificateResponse{
		SubjectAN:    cert.DNSNames,
		Emails:       cert.EmailAddresses,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		Expired:      IsExpired(cert.NotAfter),
		SelfSigned:   IsSelfSigned(cert.AuthorityKeyId, cert.SubjectKeyId),
		MisMatched:   IsMisMatchedCert(hostname, append(cert.DNSNames, cert.Subject.CommonName)),
		Revoked:      IsTLSRevoked(options, cert),
		WildCardCert: IsWildCardCert(append(cert.DNSNames, cert.Subject.CommonName)),
		IssuerCN:     cert.Issuer.CommonName,
		IssuerOrg:    cert.Issuer.Organization,
		SubjectCN:    cert.Subject.CommonName,
		SubjectOrg:   cert.Subject.Organization,
		FingerprintHash: CertificateResponseFingerprintHash{
			MD5:    MD5Fingerprint(cert.Raw),
			SHA1:   SHA1Fingerprint(cert.Raw),
			SHA256: SHA256Fingerprint(cert.Raw),
		},
		Serial: FormatToSerialNumber(cert.SerialNumber),
	}
	response.IssuerDN = ParseASN1DNSequenceWithZpkixOrDefault(cert.RawIssuer, cert.Issuer.String())
	response.SubjectDN = ParseASN1DNSequenceWithZpkixOrDefault(cert.RawSubject, cert.Subject.String())
	if showcert {
		response.Certificate = PemEncode(cert.Raw)
	}
	return response
}

// IntersectStringSlices returns intersection of two string slices
func IntersectStringSlices(s1 []string, s2 []string) []string {
	res := []string{}
	slicemap := map[string]struct{}{}
	var rangeslice []string

	// create a map of small slice and iterate over larger slice
	if len(s1) < len(s2) {
		for _, v := range s1 {
			slicemap[v] = struct{}{}
		}
		rangeslice = s2
	} else {
		for _, v := range s2 {
			slicemap[v] = struct{}{}
		}
		rangeslice = s1
	}
	for _, v := range rangeslice {
		if _, ok := slicemap[v]; ok {
			res = append(res, v)
		}
	}
	return res
}

// GetAddress return address string from user input
func GetConn(ctx context.Context, hostname, ip, port string, inputOpts *Options) (net.Conn, error) {
	var address string
	if iputil.IsIP(ip) && (inputOpts.ScanAllIPs || len(inputOpts.IPVersion) > 0) {
		address = net.JoinHostPort(ip, port)
	} else {
		address = net.JoinHostPort(hostname, port)
	}
	//validation
	if (hostname == "" && ip == "") || port == "" {
		return nil, errorutil.New("client requires valid address got port=%v,hostname=%v,ip=%v", port, hostname, ip)
	}
	rawConn, err := inputOpts.Fastdialer.Dial(ctx, "tcp", address)
	if err != nil {
		return nil, errorutil.New("could not dial address").Wrap(err)
	}
	if rawConn == nil {
		return nil, errorutil.New("could not connect to %s", address)
	}
	if inputOpts.Timeout == 0 {
		inputOpts.Timeout = 5
	}
	// will set both read and write deadline
	err = rawConn.SetDeadline(time.Now().Add(time.Duration(inputOpts.Timeout) * time.Second))
	return rawConn, err
}

// FormatToSerialNumber converts big.Int to colon seperated hex string
// Example: 17034156255497985825694118641198758684 -> 0C:D0:A8:BE:C6:32:CF:E6:45:EC:A0:A9:B0:84:FB:1C
func FormatToSerialNumber(serialNumber *big.Int) string {
	if serialNumber == nil || serialNumber.Cmp(big.NewInt(0)) == 0 {
		return ""
	}
	b := serialNumber.Bytes()
	if len(b) == 0 {
		return ""
	}
	buf := make([]byte, 0, 3*len(b))
	x := buf[1*len(b) : 3*len(b)]
	hex.Encode(x, b)
	for i := 0; i < len(x); i += 2 {
		buf = append(buf, x[i], x[i+1], ':')
	}
	return strings.ToUpper(string(buf[:len(buf)-1]))
}
