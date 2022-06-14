package tlsx

import (
	"strconv"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/tls"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/ztls"
)

// Service is a service for tlsx module
type Service struct {
	port    string
	options *clients.Options
	client  clients.Implementation
}

// New creates a new tlsx service module
func New(options *clients.Options) (*Service, error) {
	service := &Service{
		options: options,
		port:    strconv.Itoa(options.Port),
	}
	var err error
	if options.Zcrypto {
		service.client, err = ztls.New(options)
	} else {
		service.client, err = tls.New(options)
	}
	if err != nil {
		return nil, errors.Wrap(err, "could not create tls service")
	}
	return service, nil
}

// Connect connects to the input returning a response structure
func (s *Service) Connect(input string) (*clients.Response, error) {
	host, port, err := s.normalizeInput(input)
	if err != nil {
		return nil, errors.Wrap(err, "could not normalize input")
	}
	resp, err := s.client.Connect(host, port)
	if err != nil {
		return nil, errors.Wrap(err, "could not connect to host")
	}
	return resp, nil
}
