// Package openssl implements a tls grabbing implementation using openssl
package openssl

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/iputil"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/spacemonkeygo/openssl"

	zasn1 "github.com/zmap/zcrypto/encoding/asn1"
	zpkix "github.com/zmap/zcrypto/x509/pkix"
)

// Client is a TLS grabbing client using crypto/tls
type Client struct {
	dialer           *fastdialer.Dialer
	openSSLDialFlags []openssl.DialFlags
	options          *clients.Options
}

// New creates a new grabbing client using crypto/tls
func New(options *clients.Options) (*Client, error) {
	c := &Client{
		dialer:  options.Fastdialer,
		options: options,
	}

	if !options.VerifyServerCertificate {
		c.openSSLDialFlags = append(c.openSSLDialFlags, openssl.InsecureSkipHostVerification)
	}

	return c, nil
}

func (c *Client) OpenSSLDialFlags() openssl.DialFlags {
	if len(c.openSSLDialFlags) == 0 {
		return 0
	}
	initialFlag := c.openSSLDialFlags[0]
	allDialFlags := initialFlag
	for _, dialFlag := range c.openSSLDialFlags {
		if dialFlag != initialFlag {
			allDialFlags = allDialFlags & dialFlag
		}
	}
	return allDialFlags
}

// Connect connects to a host and grabs the response data
func (c *Client) ConnectWithOptions(hostname, ip, port string, options clients.ConnectOptions) (*clients.Response, error) {
	address := net.JoinHostPort(hostname, port)

	if c.options.ScanAllIPs || len(c.options.IPVersion) > 0 {
		address = net.JoinHostPort(ip, port)
	}

	opensslCtx, err := openssl.NewCtx()
	if err != nil {
		return nil, err
	}

	if c.options.Timeout > 0 {
		opensslCtx.SetTimeout(time.Duration(c.options.Timeout) * time.Second)
	}

	if len(c.options.Ciphers) > 0 {
		if err := opensslCtx.SetCipherList(strings.Join(c.options.Ciphers, ",")); err != nil {
			return nil, errors.Wrap(err, "could not set ciphers")
		}
	}

	if c.options.CACertificate != "" {
		caCert, err := ioutil.ReadFile(c.options.CACertificate)
		if err != nil {
			return nil, errors.Wrap(err, "could not read ca certificate")
		}
		caStore := opensslCtx.GetCertificateStore()
		err = caStore.LoadCertificatesFromPEM(caCert)
		if err != nil {
			return nil, errors.Wrap(err, "could not add certificate to store")
		}
	}

	conn, err := openssl.Dial("tcp", address, opensslCtx, c.OpenSSLDialFlags())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var resolvedIP string
	if !iputil.IsIP(hostname) {
		remoteAddr := conn.RemoteAddr().String()
		if IP, _, err := net.SplitHostPort(remoteAddr); err == nil {
			resolvedIP = IP
		}
		if resolvedIP == "" {
			resolvedIP = ip
		}
	}

	if options.SNI != "" {
		if err := conn.SetTlsExtHostName(options.SNI); err != nil {
			return nil, errors.New("could not set custom SNI")
		}
	}

	if err := conn.Handshake(); err != nil {
		return nil, errors.Wrap(err, "could not do handshake")
	}

	peerCertificates, err := conn.PeerCertificateChain()
	if err != nil {
		return nil, errors.Wrap(err, "could not get peer certificates")
	}

	if len(peerCertificates) == 0 {
		return nil, errors.New("no certificates returned by server")
	}

	tlsCipher, err := conn.CurrentCipher()
	if err != nil {
		return nil, errors.Wrap(err, "could not get current cipher")
	}

	leafCertificate := peerCertificates[0]
	certificateChain := peerCertificates[1:]
	serverName := conn.GetServername()

	x509LeafCertificate, err := c.convertOpenSSLToX509Certificate(leafCertificate)
	if err != nil {
		return nil, errors.Wrap(err, "could not convert openssl leaf certificate")
	}

	now := time.Now()
	response := &clients.Response{
		Timestamp:           &now,
		Host:                hostname,
		IP:                  resolvedIP,
		ProbeStatus:         true,
		Port:                port,
		Cipher:              tlsCipher,
		TLSConnection:       "openssl",
		CertificateResponse: c.convertCertificateToResponse(hostname, x509LeafCertificate),
		ServerName:          serverName,
	}
	if c.options.TLSChain {
		for _, opensslCert := range certificateChain {
			x509Cert, err := c.convertOpenSSLToX509Certificate(opensslCert)
			if err != nil {
				return nil, errors.Wrap(err, "could not convert openssl chain certificate")
			}
			response.Chain = append(response.Chain, c.convertCertificateToResponse(hostname, x509Cert))
		}
	}
	return response, nil
}

func (c *Client) convertOpenSSLToX509Certificate(opensslCert *openssl.Certificate) (*x509.Certificate, error) {
	pemBytes, err := opensslCert.MarshalPEM()
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal openssl to pem x509")
	}
	pemBlock, _ := pem.Decode(pemBytes)
	if err != nil {
		return nil, errors.Wrap(err, "could not read openssl pem x509 to go pem")
	}
	if pemBlock.Type != "CERTIFICATE" {
		return nil, errors.Wrap(err, "unsupported pem block type")
	}
	x509Certificate, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "could not convert openssl x509 to go x509")
	}

	return x509Certificate, nil
}

func (c *Client) convertCertificateToResponse(hostname string, cert *x509.Certificate) *clients.CertificateResponse {
	response := &clients.CertificateResponse{
		SubjectAN:  cert.DNSNames,
		Emails:     cert.EmailAddresses,
		NotBefore:  cert.NotBefore,
		NotAfter:   cert.NotAfter,
		Expired:    clients.IsExpired(cert.NotAfter),
		SelfSigned: clients.IsSelfSigned(cert.AuthorityKeyId, cert.SubjectKeyId),
		MisMatched: clients.IsMisMatchedCert(hostname, append(cert.DNSNames, cert.Subject.CommonName)),
		IssuerCN:   cert.Issuer.CommonName,
		IssuerOrg:  cert.Issuer.Organization,
		SubjectCN:  cert.Subject.CommonName,
		SubjectOrg: cert.Subject.Organization,
		FingerprintHash: clients.CertificateResponseFingerprintHash{
			MD5:    clients.MD5Fingerprint(cert.Raw),
			SHA1:   clients.SHA1Fingerprint(cert.Raw),
			SHA256: clients.SHA256Fingerprint(cert.Raw),
		},
	}
	if parsedIssuer := parseASN1DNSequenceWithZpkix(cert.RawIssuer); parsedIssuer != "" {
		response.IssuerDN = parsedIssuer
	} else {
		response.IssuerDN = cert.Issuer.String()
	}
	if parsedSubject := parseASN1DNSequenceWithZpkix(cert.RawSubject); parsedSubject != "" {
		response.SubjectDN = parsedSubject
	} else {
		response.SubjectDN = cert.Subject.String()
	}
	if c.options.Cert {
		response.Certificate = clients.PemEncode(cert.Raw)
	}
	return response
}

// parseASN1DNSequenceWithZpkix tries to parse raw ASN1 of a TLS DN with zpkix and
// zasn1 library which includes additional information not parsed by go standard
// library which may be useful.
//
// If the parsing fails, a blank string is returned and the standard library data is used.
func parseASN1DNSequenceWithZpkix(data []byte) string {
	var rdnSequence zpkix.RDNSequence
	var subject zpkix.Name
	if _, err := zasn1.Unmarshal(data, &rdnSequence); err != nil {
		return ""
	}
	subject.FillFromRDNSequence(&rdnSequence)
	dnParsedString := subject.String()
	return dnParsedString
}
