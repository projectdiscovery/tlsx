package auto

import (
	"testing"

	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/stretchr/testify/require"
)

func TestAutoRejectsTLSGroups(t *testing.T) {
	options := &clients.Options{
		TLSGroups: []string{"X25519MLKEM768"},
	}
	client, err := New(options)
	require.Error(t, err)
	require.Nil(t, client)
	require.Contains(t, err.Error(), "tls-groups is only supported with scan-mode ctls")
}
