package clients

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/goflags"
)

// Implementation is an interface implemented by TLSX client
type Implementation interface {
	// Connect connects to a host and grabs the response data
	Connect(hostname, port string) (*Response, error)
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
	ServerName string
	// Verbose enables display of verbose output
	Verbose bool
	// Version shows the version of the program
	Version bool
	// JSON enables display of JSON output
	JSON bool
	// TLSChain enables printing TLS chain information to output
	TLSChain bool
	// CertsOnly enables early SSL termination using ztls flag
	CertsOnly bool
	// Timeout is the number of seconds to wait for connection
	Timeout int
	// Concurrency is the number of concurrent threads to process
	Concurrency int
	// Port is the ports to make request to
	Ports goflags.StringSlice
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

	// Fastdialer is a fastdialer dialer instance
	Fastdialer *fastdialer.Dialer
}

// Response is the response returned for a TLS grab event
type Response struct {
	// Timestamp is the timestamp for certificate response
	Timestamp time.Time `json:"timestamp,omitempty"`
	// Host is the host to make request to
	Host string `json:"host"`
	// IP is the IP address the request was made to
	IP string `json:"ip,omitempty"`
	// Port is the port to make request to
	Port string `json:"port"`
	// Version is the tls version responded by the server
	Version string `json:"tls-version"`
	// Cipher is the cipher for the tls request
	Cipher string `json:"cipher,omitempty"`
	// CertificateResponse is the leaf certificate embedded in json
	CertificateResponse `json:",inline"`
	// TLSConnection is the client used for TLS connection
	// when ran using scan-mode auto.
	TLSConnection string `json:"tls-connection,omitempty"`
	// Chain is the chain of certificates
	Chain []CertificateResponse `json:"chain,omitempty"`
}

// CertificateResponse is the response for a certificate
type CertificateResponse struct {
	// Expired specifies whether the certificate has expired
	Expired bool `json:"expired"`
	// NotBefore is the not-before time for certificate
	NotBefore time.Time `json:"not-before,omitempty"`
	// NotAfter is the not-after time for certificate
	NotAfter time.Time `json:"not-after,omitempty"`
	// SubjectDN is the distinguished name for cert
	SubjectDN string `json:"subject-dn,omitempty"`
	// SubjectCN is the common name for cert
	SubjectCN string `json:"subject-cn,omitempty"`
	// SubjectAN is a list of Subject Alternative Names for the certificate
	SubjectAN []string `json:"subject-an,omitempty"`
	// IssuerDN is the distinguished name for cert
	IssuerDN string `json:"issuer-dn,omitempty"`
	// IssuerCN is the common name for cert
	IssuerCN string `json:"issuer-cn,omitempty"`
	// Emails is a list of Emails for the certificate
	Emails []string `json:"emails,omitempty"`
	// FingerprintHash is the hashes for certificate
	FingerprintHash CertificateResponseFingerprintHash `json:"fingerprint-hash"`
}

// CertificateDistinguishedName is a distinguished certificate name
type CertificateDistinguishedName struct {
	Country            []string `json:"country,omitempty"`
	Organization       []string `json:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizational-unit,omitempty"`
	Locality           []string `json:"locality,omitempty"`
	Province           []string `json:"province,omitempty"`
	StreetAddress      []string `json:"street-address,omitempty"`
	CommonName         string   `json:"common-name,omitempty"`
}

// CertificateResponseFingerprintHash is a response for fingerprint hash of cert
type CertificateResponseFingerprintHash struct {
	// MD5 is the md5 hash for certificate
	MD5 string `json:"md5"`
	// SHA1 is the sha1 hash for certificate
	SHA1 string `json:"sha1"`
	// SHA256 is the sha256 hash for certificate
	SHA256 string `json:"sha256"`
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
