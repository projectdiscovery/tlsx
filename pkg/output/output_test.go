package output

import (
	"testing"

	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/stretchr/testify/require"
)

func TestStandardWriter_formatStandard(t *testing.T) {
	stdWriter := StandardWriter{}

	t.Run("Empty certificate", func(t *testing.T) {
		out, err := stdWriter.formatStandard(nil)
		require.Nil(t, out)
		require.Error(t, err)
	})

	t.Run("Empty certificate leaf", func(t *testing.T) {
		out, err := stdWriter.formatStandard(&clients.Response{})
		require.Nil(t, out)
		require.Error(t, err)
	})
}
