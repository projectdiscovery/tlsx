package tlsx

import (
	"strconv"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/auto"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/jarm"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/openssl"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/tls"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/ztls"
	errorutil "github.com/projectdiscovery/utils/errors"
	sliceutil "github.com/projectdiscovery/utils/slice"
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
	if options.Fastdialer == nil {
		var err error
		options.Fastdialer, err = fastdialer.NewDialer(fastdialer.DefaultOptions)
		if err != nil {
			return nil, err
		}
	}

	var err error
	switch options.ScanMode {
	case "ztls":
		service.client, err = ztls.New(options)
	case "ctls":
		service.client, err = tls.New(options)
	case "openssl":
		service.client, err = openssl.New(options)
	case "auto":
		service.client, err = auto.New(options)
	default:
		// Default mode is TLS
		service.client, err = tls.New(options)
		options.ScanMode = "ctls"
	}
	if err != nil {
		return nil, errorutil.NewWithTag("auto", "could not create tls service").Wrap(err)
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

	//validation
	if (host == "" && ip == "") || port == "" {
		return nil, errorutil.NewWithTag("tlsx", "tlsx requires valid address got port=%v,hostname=%v,ip=%v", port, host, ip)
	}

	if s.options.ScanMode != "auto" && s.options.ScanMode != "" {
		// auto mode uses different modes as fallback
		// hence that can be considered as retry
		for i := 0; i < s.options.Retries; i++ {
			if resp, err = s.client.ConnectWithOptions(host, ip, port, options); resp != nil {
				err = nil
				break
			}
		}
	} else {
		if resp, err = s.client.ConnectWithOptions(host, ip, port, options); resp != nil {
			err = nil
		}
	}
	if resp == nil && err == nil {
		return nil, errorutil.NewWithTag("auto", "no response returned for connection")
	}
	if err != nil {
		wrappedErr := errorutil.NewWithTag("auto", "could not connect to host").Wrap(err)
		if s.options.ProbeStatus {
			return &clients.Response{Host: host, Port: port, Error: err.Error(), ProbeStatus: false, ServerName: options.SNI}, wrappedErr
		}
		return nil, wrappedErr
	}

	if s.options.Jarm {
		port, _ := strconv.Atoi(port)
		jarmhash, err := jarm.HashWithDialer(s.options.Fastdialer, host, port, s.options.Timeout)
		if err != nil {
			return resp, err
		}
		resp.JarmHash = jarmhash
	}

	if s.options.TlsVersionsEnum {
		options.EnumMode = clients.Version
		supportedTlsVersions := []string{resp.Version}
		enumeratedTlsVersions, _ := s.enumTlsVersions(host, ip, port, options)
		supportedTlsVersions = append(supportedTlsVersions, enumeratedTlsVersions...)
		resp.VersionEnum = sliceutil.Dedupe(supportedTlsVersions)
	}

	var supportedTlsCiphers []clients.TlsCiphers
	if s.options.TlsCiphersEnum {
		options.EnumMode = clients.Cipher
		if !s.options.Silent {
			gologger.Info().Msgf("Started TLS Cipher Enumeration using %v mode", s.options.ScanMode)
		}
		for _, supportedTlsVersion := range resp.VersionEnum {
			options.VersionTLS = supportedTlsVersion
			enumeratedTlsCiphers, _ := s.enumTlsCiphers(host, ip, port, options)
			enumeratedTlsCiphers = sliceutil.Dedupe(enumeratedTlsCiphers)
			cipherTypes := clients.IdentifyCiphers(enumeratedTlsCiphers)
			supportedTlsCiphers = append(supportedTlsCiphers, clients.TlsCiphers{Version: supportedTlsVersion, Ciphers: cipherTypes})
		}
		resp.TlsCiphers = supportedTlsCiphers
	}
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

func (s *Service) enumTlsCiphers(host, ip, port string, options clients.ConnectOptions) ([]string, error) {
	options.EnumMode = clients.Cipher
	for _, cipher := range s.options.TLsCipherLevel {

		switch cipher {
		case "weak":
			options.CipherLevel = append(options.CipherLevel, clients.Weak)
		case "secure":
			options.CipherLevel = append(options.CipherLevel, clients.Secure)
		case "insecure":
			options.CipherLevel = append(options.CipherLevel, clients.Insecure)
		default:
			options.CipherLevel = append(options.CipherLevel, clients.All)
		}
	}
	return s.client.EnumerateCiphers(host, ip, port, options)
}
