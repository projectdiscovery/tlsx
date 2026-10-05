package tls

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestToTLSGroups verifies group name parsing, canonical names and rejection
// of unknown, empty and duplicate names.
func TestToTLSGroups(t *testing.T) {
	groups, names, err := toTLSGroups([]string{"X25519MLKEM768", "x25519", "CURVEP256", "CurveP384", "CurveP521"})
	require.NoError(t, err)
	require.Equal(t, []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521}, groups)
	require.Equal(t, []string{"X25519MLKEM768", "X25519", "CurveP256", "CurveP384", "CurveP521"}, names)

	for _, invalid := range [][]string{
		{"X448"},
		{""},
		{"23"},
		{"X25519", "x25519"},
	} {
		_, _, err := toTLSGroups(invalid)
		require.Error(t, err, "%v", invalid)
	}
}

// TestSupportedTLSGroups ensures every advertised group name maps to a curve
// whose crypto/tls name is the same canonical spelling.
func TestSupportedTLSGroups(t *testing.T) {
	require.Len(t, tlsGroups, len(SupportedTLSGroups))
	for _, name := range SupportedTLSGroups {
		group, ok := tlsGroups[name]
		require.True(t, ok, name)
		require.Equal(t, name, group.String(), "canonical name must match crypto/tls")
	}
}
