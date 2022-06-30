package jarm

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	gojarm "github.com/hdm/jarm-go"
	"github.com/projectdiscovery/fastdialer/fastdialer"
)

// fingerprint probes a single host/port
func HashWithDialer(dialer *fastdialer.Dialer, host string, port int, timeout time.Duration) (string, error) {
	results := []string{}
	for _, probe := range gojarm.GetProbes(host, port) {
		addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
		c, err := dialer.Dial(context.Background(), "tcp", addr)
		if err != nil {
			continue
		}
		if c == nil {
			continue
		}
		_ = c.SetWriteDeadline(time.Now().Add(timeout))
		_, err = c.Write(gojarm.BuildProbe(probe))
		if err != nil {
			results = append(results, "")
			_ = c.Close()
			continue
		}
		_ = c.SetReadDeadline(time.Now().Add(timeout))
		buff := make([]byte, 1484)
		_, _ = c.Read(buff)
		_ = c.Close()
		ans, err := gojarm.ParseServerHello(buff, probe)
		if err != nil {
			results = append(results, "")
			continue
		}
		results = append(results, ans)
	}
	hash := gojarm.RawHashToFuzzyHash(strings.Join(results, ","))
	return hash, nil
}
