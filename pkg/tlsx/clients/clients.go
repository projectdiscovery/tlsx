package clients

import "github.com/projectdiscovery/goflags"

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
	// Zcrypto enables using of zmap/zcrypto library instead of crypto/tls
	Zcrypto bool
	// VerifyServerCertificate enables optional verification of server certificates
	VerifyServerCertificate bool
}

// Response is the response returned for a TLS grab event
type Response struct {
	// Host is the host to make request to
	Host string `json:"host"`
	// Port is the port to make request to
	Port string `json:"port"`
	// Version is the tls version responded by the server
	Version string `json:"version"`
	// Leaf is the leaf certificate response
	Leaf CertificateResponse `json:"leaf"`
	// Chain is the chain of certificates
	Chain []CertificateResponse `json:"chain,omitempty"`
}

// CertificateResponse is the response for a certificate
type CertificateResponse struct {
	// DNSNames is a list of DNS names for the certificate
	DNSNames []string `json:"dns-names,omitempty"`
	// Emails is a list of Emails for the certificate
	Emails []string `json:"emails,omitempty"`
	// IssuerCommonName is the common-name for the issuer
	IssuerCommonName string `json:"issuer-common-name,omitempty"`
	// SubjectCommonName is the common-name for the subject
	SubjectCommonName string `json:"subject-common-name,omitempty"`
	// IssuerOrganization is the organization for the issuer
	IssuerOrganization []string `json:"issuer-organization,omitempty"`
	// SubjectOrganization is the organization for the subject
	SubjectOrganization []string `json:"subject-organization,omitempty"`
}
