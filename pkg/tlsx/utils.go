package tlsx

import (
	"net"
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

// normalizeInput normalizes different inputs to a final host:port representation
func (s *Service) normalizeInput(input string) (string, string, error) {
	host := input

	// Handle URL input
	if strings.Contains(input, "://") {
		parsed, err := url.Parse(input)
		if err != nil {
			return "", "", errors.Wrap(err, "could not parse url")
		}
		if parsed.Host != "" {
			host = parsed.Host
		} else {
			return "", "", errors.Wrap(err, "could not get url host")
		}
	}
	// Handle host with port
	if strings.Contains(host, ":") {
		hostname, port, err := net.SplitHostPort(host)
		if err != nil {
			return "", "", errors.Wrap(err, "could not split host port")
		}
		return hostname, port, nil
	}
	// Return if we don't have a default port
	if s.port == "" {
		return "", "", errors.New("no port specified and found")
	}
	return host, s.port, nil
}
