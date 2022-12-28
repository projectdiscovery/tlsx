package tlsx_test

import (
	"errors"
	"testing"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/tlsx/pkg/tlsx"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/openssl"
	iputil "github.com/projectdiscovery/utils/ip"
)

func TestResolvedIP(t *testing.T) {
	allmodes := []string{"openssl", "ctls", "ztls", "auto"}
	targethostname := "scanme.sh"
	targets, err := getDNSdata(targethostname)
	if err != nil {
		t.Fatalf("failed to get dns data: %v", err)
	}

	for _, mode := range allmodes {
		client, err := tlsx.New(&clients.Options{
			ScanMode: mode,
			Retries:  3,
			Timeout:  3,
		})
		if errors.Is(err, openssl.ErrNotAvailable) {
			t.Logf("openssl not available skipping..")
			continue
		}
		if err != nil {
			t.Fatalf("failed to create new client for %v mode: %v", mode, err)
		}
		for _, target := range targets {
			resp, err := client.ConnectWithOptions(targethostname, target, "443", clients.ConnectOptions{})
			if err != nil {
				if iputil.IsIPv6(target) {
					t.Logf("ipv6 potentially not supported skipping..")
					continue
				}
				t.Fatalf("%v: failed to get response from tlsx client: %v", mode, err)
			}
			if !iputil.IsIP(resp.IP) {
				t.Fatalf("%v: expected ip address for %v but got %v for mode %v", mode, target, resp.IP, mode)
			}
		}
	}

}

func getDNSdata(hostname string) ([]string, error) {
	targets := []string{}
	fd, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
	if err != nil {
		return targets, err
	}
	dnsData, err := fd.GetDNSData(hostname)
	if err != nil {
		return targets, err
	}
	targets = append(targets, hostname)
	targets = append(targets, dnsData.A...)
	targets = append(targets, dnsData.AAAA...)

	return targets, nil
}
