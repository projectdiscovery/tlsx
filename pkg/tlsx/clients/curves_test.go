package clients

import (
	"crypto/tls"
	"reflect"
	"testing"
)

func TestToCurveIDs(t *testing.T) {
	tests := []struct {
		name        string
		input       []string
		expected    []tls.CurveID
		expectError bool
	}{
		{
			name:        "empty list",
			input:       []string{},
			expected:    nil,
			expectError: false,
		},
		{
			name:        "nil list",
			input:       nil,
			expected:    nil,
			expectError: false,
		},
		{
			name:        "canonical names",
			input:       []string{"X25519MLKEM768", "X25519", "CurveP256", "CurveP384", "CurveP521"},
			expected:    []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521},
			expectError: false,
		},
		{
			name:        "case-insensitive and formatted aliases",
			input:       []string{"x25519mlkem768", "x25519_mlkem768", "p-256", "SECP384R1", "P521"},
			expected:    []tls.CurveID{tls.X25519MLKEM768, tls.X25519MLKEM768, tls.CurveP256, tls.CurveP384, tls.CurveP521},
			expectError: false,
		},
		{
			name:        "numeric codepoints",
			input:       []string{"4588", "29", "23"},
			expected:    []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256},
			expectError: false,
		},
		{
			name:        "preserves exact ordering",
			input:       []string{"CurveP384", "X25519", "CurveP256"},
			expected:    []tls.CurveID{tls.CurveP384, tls.X25519, tls.CurveP256},
			expectError: false,
		},
		{
			name:        "unsupported group name",
			input:       []string{"X25519", "NonExistentCurve"},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "unsupported numeric ID",
			input:       []string{"99999"},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToCurveIDs(tt.input)
			if (err != nil) != tt.expectError {
				t.Fatalf("ToCurveIDs() error = %v, expectError = %v", err, tt.expectError)
			}
			if !tt.expectError && !reflect.DeepEqual(got, tt.expected) {
				t.Fatalf("ToCurveIDs() got = %v, want = %v", got, tt.expected)
			}
		})
	}
}

func TestCurveIDsToNames(t *testing.T) {
	curves := []tls.CurveID{
		tls.X25519MLKEM768,
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
		tls.CurveP521,
		tls.SecP256r1MLKEM768,
		tls.SecP384r1MLKEM1024,
		tls.MLKEM1024,
	}

	expected := []string{
		"X25519MLKEM768",
		"X25519",
		"CurveP256",
		"CurveP384",
		"CurveP521",
		"SecP256r1MLKEM768",
		"SecP384r1MLKEM1024",
		"MLKEM1024",
	}

	got := CurveIDsToNames(curves)
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("CurveIDsToNames() got = %v, want = %v", got, expected)
	}

	if CurveIDsToNames(nil) != nil {
		t.Fatalf("CurveIDsToNames(nil) expected nil, got %v", CurveIDsToNames(nil))
	}
}
