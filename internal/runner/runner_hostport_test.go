package runner

import "testing"

func TestGetHostPortFromInput(t *testing.T) {
	t.Parallel()

	r := &Runner{}

	tests := []struct {
		name        string
		input       string
		wantHost    string
		wantPort    string
	}{
		{name: "domain", input: "example.com", wantHost: "example.com", wantPort: ""},
		{name: "domain-port", input: "example.com:8443", wantHost: "example.com", wantPort: "8443"},
		{name: "https-url", input: "https://example.com:8443/path", wantHost: "example.com", wantPort: "8443"},
		{name: "ipv4", input: "1.2.3.4", wantHost: "1.2.3.4", wantPort: ""},
		{name: "ipv4-port", input: "1.2.3.4:443", wantHost: "1.2.3.4", wantPort: "443"},
		{name: "ipv6", input: "2a03:2880:11ff:17::face:b00c", wantHost: "2a03:2880:11ff:17::face:b00c", wantPort: ""},
		{name: "ipv6-bracket-port", input: "[2a03:2880:11ff:17::face:b00c]:443", wantHost: "2a03:2880:11ff:17::face:b00c", wantPort: "443"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			host, port := r.getHostPortFromInput(tt.input)
			if host != tt.wantHost {
				t.Fatalf("host mismatch: want=%q got=%q", tt.wantHost, host)
			}
			if port != tt.wantPort {
				t.Fatalf("port mismatch: want=%q got=%q", tt.wantPort, port)
			}
		})
	}
}
