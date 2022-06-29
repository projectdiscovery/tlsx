package tlsx

import (
	"github.com/pkg/errors"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/auto"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
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
func (s *Service) Connect(host, port string) (*clients.Response, error) {
	resp, err := s.client.Connect(host, port)
	if err != nil {
		wrappedErr := errors.Wrap(err, "could not connect to host")
		if s.options.ErrorsInJSON {
			return &clients.Response{Host: host, Port: port, Error: err.Error(), ProbeStatus: false}, wrappedErr
		}
		return nil, wrappedErr
	}
	return resp, nil
}
