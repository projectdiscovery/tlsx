package clients

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/revoke"
	"github.com/logrusorgru/aurora"
	zasn1 "github.com/zmap/zcrypto/encoding/asn1"
	zpkix "github.com/zmap/zcrypto/x509/pkix"

	zx509 "github.com/zmap/zcrypto/x509"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/tlsx/assets"
	stringsutil "github.com/projectdiscovery/utils/strings"
	ztls "github.com/zmap/zcrypto/tls"
)

// Implementation is an interface implemented by TLSX client
type Implementation interface {
	// Connect connects to a host and grabs the response data
	ConnectWithOptions(hostname, ip, port string, options ConnectOptions) (*Response, error)

	EnumerateCiphers(hostname, ip, port string, options ConnectOptions) ([]string, error)

	// SupportedTLSVersions returns the list of supported tls versions
	SupportedTLSVersions() ([]string, error)
	// SupportedTLSCiphers returns the list of supported tls ciphers
	SupportedTLSCiphers() ([]string, error)
}

// Options contains configuration options for tlsx client
type Options struct {
	// OutputFile is the file to write output to
	OutputFile string
	// Inputs is a list of inputs to process
	Inputs goflags.StringSlice
	// InputList is the list of inputs to process
	InputList string
	// ServerName is the optional server-name for tls connection
	ServerName goflags.StringSlice
	// RandomForEmptyServerName in case of empty sni
	RandomForEmptyServerName bool
	// ReversePtrSNI performs a reverse PTR query to obtain SNI from IP
	ReversePtrSNI bool
	// Verbose enables display of verbose output
	Verbose bool
	// Version shows the version of the program
	Version bool
	// JSON enables display of JSON output
	JSON bool
	// TLSChain enables printing TLS chain information to output
	TLSChain bool
	// Deprecated: AllCiphers exists for historical compatibility and should not be used
	AllCiphers bool
	// ProbeStatus enables writing of errors with json output
	ProbeStatus bool
	// CertsOnly enables early SSL termination using ztls flag
	CertsOnly bool
	// RespOnly displays TLS respones only in CLI output
	RespOnly bool
	// Silent enables silent output display
	Silent bool
	// NoColor disables coloring of CLI output
	NoColor bool
	// Retries is the number of times to retry TLS connection
	Retries int
	// Timeout is the number of seconds to wait for connection
	Timeout int
	// Concurrency is the number of concurrent threads to process
	Concurrency int
	// Delay is the duration to wait between requests in each thread
	Delay string
	// Port is the ports to make request to
	Ports goflags.StringSlice
	// Ciphers is a list of custom ciphers to use for connection
	Ciphers goflags.StringSlice
	// CACertificate is the CA certificate for connection
	CACertificate string
	// MinVersion is the minimum tls version that is acceptable
	MinVersion string
	// MaxVersion is the maximum tls version that is acceptable
	MaxVersion string
	// Resolvers contains custom resolvers for the tlsx client
	Resolvers goflags.StringSlice
	// ScanMode is the tls connection mode to use
	ScanMode string
	// VerifyServerCertificate enables optional verification of server certificates
	VerifyServerCertificate bool
	// OpenSSL Binary Path
	OpenSSLBinary string
	// SAN displays Subject Alternative Names
	SAN bool
	// CN displays Subject Common Name
	CN bool
	// SO displays Subject Organization Name
	SO bool
	// TLSVersion displays used TLS version
	TLSVersion bool
	// Cipher displays used cipher
	Cipher bool
	// Expired displays validity of TLS certificate
	Expired bool
	// SelfSigned displays if cert is self-signed
	SelfSigned bool
	// Untrusted displays if cert is untrusted
	Untrusted bool
	// MisMatched displays if the cert is mismatched
	MisMatched bool
	// Revoked displays if the cert is revoked
	Revoked bool
	// HardFail defines Revoke status when there are parse failures or other errors
	// If HardFail is true then on any error certificate is considered as revoked
	HardFail bool
	// Hash is the hash to display for certificate
	Hash string
	// Jarm calculate jarm fingerprinting with multiple probes
	Jarm bool
	// Cert displays certificate in pem format
	Cert bool
	// Ja3 displays ja3 fingerprint hash
	Ja3 bool
	// Scan all IP's
	ScanAllIPs bool
	// IP Version to use for scanning
	IPVersion goflags.StringSlice
	// WildcardCertCheck enables wildcard certificate check
	WildcardCertCheck bool
	// TlsVersionsEnum enumerates supported tls versions
	TlsVersionsEnum bool
	// TlsCiphersEnum enumerates supported ciphers per TLS protocol
	TlsCiphersEnum bool
	// TLSCipherSecLevel
	TLsCipherLevel []string
	// ClientHello include client hello (only ztls)
	ClientHello bool
	// ServerHello include server hello (only ztls)
	ServerHello bool
	// HealthCheck performs a capabilities healthcheck
	HealthCheck bool
	// DisableUpdateCheck disables checking update
	DisableUpdateCheck bool
	// CipherConcurrency
	CipherConcurrency int

	// Fastdialer is a fastdialer dialer instance
	Fastdialer *fastdialer.Dialer
	// Serail displays certiface serial number
	Serial bool
}

// Response is the response returned for a TLS grab event
type Response struct {
	// Timestamp is the timestamp for certificate response
	Timestamp *time.Time `json:"timestamp,omitempty"`
	// Host is the host to make request to
	Host string `json:"host"`
	// IP is the IP address the request was made to
	IP string `json:"ip,omitempty"`
	// Port is the port to make request to
	Port string `json:"port"`
	// ProbeStatus is false if the tls probe failed
	ProbeStatus bool `json:"probe_status"`
	// Error is the optional error for tls request included
	// with errors_json flag.
	Error string `json:"error,omitempty"`
	// Version is the tls version responded by the server
	Version string `json:"tls_version,omitempty"`
	// Cipher is the cipher for the tls request
	Cipher string `json:"cipher,omitempty"`
	// CertificateResponse is the leaf certificate embedded in json
	*CertificateResponse `json:",inline"`
	// TLSConnection is the client used for TLS connection
	// when ran using scan-mode auto.
	TLSConnection string `json:"tls_connection,omitempty"`
	// Chain is the chain of certificates
	Chain       []*CertificateResponse `json:"chain,omitempty"`
	JarmHash    string                 `json:"jarm_hash,omitempty"`
	Ja3Hash     string                 `json:"ja3_hash,omitempty"`
	ServerName  string                 `json:"sni,omitempty"`
	VersionEnum []string               `json:"version_enum,omitempty"`
	TlsCiphers  []TlsCiphers           `json:"cipher_enum,omitempty"`
	ClientHello *ztls.ClientHello      `json:"client_hello,omitempty"`
	ServerHello *ztls.ServerHello      `json:"servers_hello,omitempty"`
}

type TlsCiphers struct {
	Version string      `json:"version,omitempty"`
	Ciphers CipherTypes `json:"ciphers,omitempty"`
}

type CipherTypes struct {
	Weak     []string `json:"weak,omitempty"`
	Insecure []string `json:"insecure,omitempty"`
	Secure   []string `json:"secure,omitempty"`
	Unknown  []string `json:"unknown,omitempty"` // cipher type not know to tlsx
}

// ColorCode returns a clone of CipherTypes with Colored Strings
func (c *CipherTypes) ColorCode(a aurora.Aurora) CipherTypes {
	ct := CipherTypes{}
	for _, v := range c.Weak {
		ct.Weak = append(ct.Weak, a.BrightYellow(v).String())
	}
	for _, v := range c.Insecure {
		ct.Insecure = append(ct.Insecure, a.BrightRed(v).String())
	}
	for _, v := range c.Secure {
		ct.Secure = append(ct.Secure, a.BrightGreen(v).String())
	}
	for _, v := range c.Unknown {
		ct.Unknown = append(ct.Unknown, a.BrightMagenta(v).String())
	}
	return ct
}

// IdentifyCiphers identifies type of ciphers from given cipherList
func IdentifyCiphers(cipherList []string) CipherTypes {
	ct := CipherTypes{}
	for _, v := range cipherList {
		switch GetCipherLevel(v) {
		case Insecure:
			ct.Insecure = append(ct.Insecure, v)
		case Secure:
			ct.Secure = append(ct.Secure, v)
		case Weak:
			ct.Weak = append(ct.Weak, v)
		default:
			ct.Unknown = append(ct.Unknown, v)
		}
	}
	return ct
}

// CertificateResponse is the response for a certificate
type CertificateResponse struct {
	// Expired specifies whether the certificate has expired
	Expired bool `json:"expired,omitempty"`
	// SelfSigned returns true if the certificate is self-signed
	SelfSigned bool `json:"self_signed,omitempty"`
	// MisMatched returns true if the certificate is mismatched
	MisMatched bool `json:"mismatched,omitempty"`
	// Revoked returns true if the certificate is revoked
	Revoked bool `json:"revoked,omitempty"`
	// Untrusted is true if the certificate is untrusted
	Untrusted bool `json:"untrusted,omitempty"`
	// NotBefore is the not-before time for certificate
	NotBefore time.Time `json:"not_before,omitempty"`
	// NotAfter is the not-after time for certificate
	NotAfter time.Time `json:"not_after,omitempty"`
	// SubjectDN is the distinguished name for cert
	SubjectDN string `json:"subject_dn,omitempty"`
	// SubjectCN is the common name for cert
	SubjectCN string `json:"subject_cn,omitempty"`
	// SubjectOrg is the organization for cert subject
	SubjectOrg []string `json:"subject_org,omitempty"`
	// SubjectAN is a list of Subject Alternative Names for the certificate
	SubjectAN []string `json:"subject_an,omitempty"`
	//Serial is the certificate serial number
	Serial string `json:"serial,omitempty"`
	// IssuerDN is the distinguished name for cert
	IssuerDN string `json:"issuer_dn,omitempty"`
	// IssuerCN is the common name for cert
	IssuerCN string `json:"issuer_cn,omitempty"`
	// IssuerOrg is the organization for cert issuer
	IssuerOrg []string `json:"issuer_org,omitempty"`
	// Emails is a list of Emails for the certificate
	Emails []string `json:"emails,omitempty"`
	// FingerprintHash is the hashes for certificate
	FingerprintHash CertificateResponseFingerprintHash `json:"fingerprint_hash,omitempty"`
	// Certificate is the raw certificate in PEM format
	Certificate string `json:"certificate,omitempty"`
	// WildCardCert is true if tls certificate is a wildcard certificate
	WildCardCert bool `json:"wildcard_certificate,omitempty"`
}

// CertificateDistinguishedName is a distinguished certificate name
type CertificateDistinguishedName struct {
	Country            []string `json:"country,omitempty"`
	Organization       []string `json:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizational_unit,omitempty"`
	Locality           []string `json:"locality,omitempty"`
	Province           []string `json:"province,omitempty"`
	StreetAddress      []string `json:"street_address,omitempty"`
	CommonName         string   `json:"common_name,omitempty"`
}

// CertificateResponseFingerprintHash is a response for fingerprint hash of cert
type CertificateResponseFingerprintHash struct {
	// MD5 is the md5 hash for certificate
	MD5 string `json:"md5,omitempty"`
	// SHA1 is the sha1 hash for certificate
	SHA1 string `json:"sha1,omitempty"`
	// SHA256 is the sha256 hash for certificate
	SHA256 string `json:"sha256,omitempty"`
}

// MD5Fingerprint creates a fingerprint of data using the MD5 hash algorithm.
func MD5Fingerprint(data []byte) string {
	sum := md5.Sum(data)
	return hex.EncodeToString(sum[:])
}

// SHA1Fingerprint creates a fingerprint of data using the SHA1 hash algorithm.
func SHA1Fingerprint(data []byte) string {
	sum := sha1.Sum(data)
	return hex.EncodeToString(sum[:])
}

// SHA256Fingerprint creates a fingerprint of data using the SHA256 hash
// algorithm.
func SHA256Fingerprint(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// IsExpired returns true if the certificate has expired
func IsExpired(notAfter time.Time) bool {
	remaining := math.Round(time.Since(notAfter).Seconds())
	return remaining > 0
}

// IsSelfSigned returns true if the certificate is self-signed
//
// follows: https://security.stackexchange.com/a/162263/250973
func IsSelfSigned(authorityKeyID, subjectKeyID []byte) bool {
	if len(authorityKeyID) == 0 || bytes.Equal(authorityKeyID, subjectKeyID) {
		return true
	}
	return false
}

// IsMisMatchedCert returns true if cert names(subject common name + alternative names) does not contain host
func IsMisMatchedCert(host string, alternativeNames []string) bool {
	hostTokens := strings.Split(host, ".")
	for _, alternativeName := range alternativeNames {
		// if not wildcard, return false if name matches the host
		if !strings.Contains(alternativeName, "*") {
			if strings.EqualFold(alternativeName, host) {
				return false
			}
		} else {
			// try to match the wildcard name with host
			nameTokens := strings.Split(alternativeName, ".")
			if len(hostTokens) == len(nameTokens) {
				matched := false
				for i, token := range nameTokens {
					if i == 0 {
						// match leftmost token
						matched = matchWildCardToken(token, hostTokens[i])
						if !matched {
							break
						}
					} else {
						// match all other tokens
						matched = stringsutil.EqualFoldAny(token, hostTokens[i])
						if !matched {
							break
						}
					}
				}
				// return false if all the name tokens matched the host tokens
				if matched {
					return false
				}
			}
		}
	}
	return true
}

// IsTLSRevoked returns true if the certificate has been revoked or failed to parse
func IsTLSRevoked(options *Options, cert *x509.Certificate) bool {
	if cert == nil {
		return options.HardFail
	}
	// - false, false: an error was encountered while checking revocations.
	// - false, true:  the certificate was checked successfully, and it is not revoked.
	// - true, true:   the certificate was checked successfully, and it is revoked.
	// - true, false:  failure to check revocation status causes verification to fail
	revoked, _ := revoke.VerifyCertificate(cert)
	return revoked
}

// IsZTLSRevoked returns true if the certificate has been revoked
func IsZTLSRevoked(options *Options, cert *zx509.Certificate) bool {
	xcert, err := x509.ParseCertificate(cert.Raw)
	if err != nil {
		gologger.Debug().Msgf("ztls: failed to convert zx509->x509 while checking revocation status: %v", err)
		return options.HardFail
	}
	return IsTLSRevoked(options, xcert)
}

// IsUntrustedCA returns true if the certificate is a self-signed CA
func IsUntrustedCA(certs []*x509.Certificate) bool {
	for _, c := range certs {
		if c != nil && c.IsCA && IsSelfSigned(c.AuthorityKeyId, c.SubjectKeyId) && !assets.IsRootCert(c) {
			return true
		}
	}
	return false
}

// IsZTLSUntrustedCA returns true if the certificate is a self-signed CA
func IsZTLSUntrustedCA(certs []ztls.SimpleCertificate) bool {
	for _, cert := range certs {
		parsedCert, _ := x509.ParseCertificate(cert.Raw)
		if parsedCert != nil && parsedCert.IsCA && IsSelfSigned(parsedCert.AuthorityKeyId, parsedCert.SubjectKeyId) && !assets.IsRootCert(parsedCert) {
			return true
		}
	}
	return false
}

// matchWildCardToken matches the wildcardName token and host token
func matchWildCardToken(name, host string) bool {
	if strings.Contains(name, "*") {
		nameSubTokens := strings.Split(name, "*")
		if strings.HasPrefix(name, "*") {
			return strings.HasSuffix(host, nameSubTokens[1])
		} else if strings.HasSuffix(name, "*") {
			return strings.HasPrefix(host, nameSubTokens[0])
		} else {
			return strings.HasPrefix(host, nameSubTokens[0]) &&
				strings.HasSuffix(host, nameSubTokens[1])
		}
	}
	return strings.EqualFold(name, host)
}

// IsWildCardCert returns true if the certificate is a wildcard certificate
func IsWildCardCert(names []string) bool {
	for _, name := range names {
		if strings.Contains(name, "*.") {
			return true
		}
	}
	return false
}

// PemEncode encodes a raw certificate to PEM format.
func PemEncode(cert []byte) string {
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
		return ""
	}
	return buf.String()
}

type EnumMode uint

const (
	None EnumMode = iota
	Version
	Cipher
)

type ConnectOptions struct {
	SNI         string
	VersionTLS  string
	Ciphers     []string
	CipherLevel []CipherSecLevel // Only used in cipher enum mode
	EnumMode    EnumMode         // Enumeration Mode (version or ciphers)
}

// ParseASN1DNSequenceWithZpkixOrDefault return the parsed value of ASN1DNSequence or a default string value
func ParseASN1DNSequenceWithZpkixOrDefault(data []byte, defaultValue string) string {
	if value := ParseASN1DNSequenceWithZpkix(data); value != "" {
		return value
	}
	return defaultValue
}

// ParseASN1DNSequenceWithZpkix tries to parse raw ASN1 of a TLS DN with zpkix and
// zasn1 library which includes additional information not parsed by go standard
// library which may be useful.
//
// If the parsing fails, a blank string is returned and the standard library data is used.
func ParseASN1DNSequenceWithZpkix(data []byte) string {
	var rdnSequence zpkix.RDNSequence
	var name zpkix.Name
	if _, err := zasn1.Unmarshal(data, &rdnSequence); err != nil {
		return ""
	}
	name.FillFromRDNSequence(&rdnSequence)
	dnParsedString := name.String()
	return dnParsedString
}

func init() {
	// assign default values to cfssl
	log.Level = log.LevelError
	revoke.HTTPClient = retryablehttp.DefaultClient()
	revoke.HTTPClient.Timeout = time.Duration(5) * time.Second
}
