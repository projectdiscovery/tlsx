package tlsx

import (
	"strconv"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/sliceutil"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/auto"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/jarm"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/tls"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/ztls"
)

// Service is a service for tlsx module
type Service struct {
	options *clients.Options
	client  clients.Implementation
}

// New creates a new tlsx service module
func New(options *clients.Options) (*Service, error) {
	service := &Service{
		options: options,
	}
	var err error
	switch options.ScanMode {
	case "ztls":
		service.client, err = ztls.New(options)
	case "ctls":
		service.client, err = tls.New(options)
	case "auto":
		service.client, err = auto.New(options)
	default:
		// Default mode is TLS
		service.client, err = tls.New(options)
	}
	if err != nil {
		return nil, errors.Wrap(err, "could not create tls service")
	}
	return service, nil
}

// Connect connects to the input returning a response structure
func (s *Service) Connect(host, ip, port string) (*clients.Response, error) {
	return s.ConnectWithOptions(host, ip, port, clients.ConnectOptions{})
}

// Connect connects to the input with custom options
func (s *Service) ConnectWithOptions(host, ip, port string, options clients.ConnectOptions) (*clients.Response, error) {
	var resp *clients.Response
	var err error

	for i := 0; i < s.options.Retries; i++ {
		if resp, err = s.client.ConnectWithOptions(host, ip, port, options); resp != nil {
			err = nil
			break
		}
	}
	if resp == nil && err == nil {
		return nil, errors.New("no response returned for connection")
	}
	if err != nil {
		wrappedErr := errors.Wrap(err, "could not connect to host")
		if s.options.ProbeStatus {
			return &clients.Response{Host: host, Port: port, Error: err.Error(), ProbeStatus: false, ServerName: options.SNI}, wrappedErr
		}
		return nil, wrappedErr
	}

	if s.options.Jarm {
		port, _ := strconv.Atoi(port)
		timeout := time.Duration(s.options.Timeout) * time.Second
		jarmhash, err := jarm.HashWithDialer(s.options.Fastdialer, host, port, timeout)
		if err != nil {
			return resp, err
		}
		resp.JarmHash = jarmhash
	}

	supportedTlsVersions := []string{resp.Version}
	if s.options.TlsVersionsEnum {
		enumeratedTlsVersions, _ := s.enumTlsVersions(host, ip, port, options)
		supportedTlsVersions = append(supportedTlsVersions, enumeratedTlsVersions...)
	}
	resp.VersionEnum = sliceutil.Dedupe(supportedTlsVersions)

	return resp, nil
}

func (s *Service) enumTlsVersions(host, ip, port string, options clients.ConnectOptions) ([]string, error) {
	var enumeratedTlsVersions []string
	clientSupportedTlsVersions, err := s.client.SupportedTLSVersions()
	if err != nil {
		return nil, err
	}
	for _, tlsVersion := range clientSupportedTlsVersions {
		options.VersionTLS = tlsVersion
		if resp, err := s.client.ConnectWithOptions(host, ip, port, options); err == nil && resp != nil && resp.Version == tlsVersion {
			enumeratedTlsVersions = append(enumeratedTlsVersions, tlsVersion)
		}
	}
	return enumeratedTlsVersions, nil
}
