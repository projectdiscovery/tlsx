package output

import (
	"bufio"
	"os"
	"sync"
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

func TestStandardWriter_WriteReturnsFileWriteError(t *testing.T) {
	tempFile, err := os.CreateTemp(t.TempDir(), "output-test-*")
	require.NoError(t, err)
	require.NoError(t, tempFile.Close())

	writer := &StandardWriter{
		json:        true,
		outputFile:  &fileWriter{file: tempFile, writer: bufio.NewWriterSize(tempFile, 1)},
		outputMutex: &sync.Mutex{},
		options:     &clients.Options{},
	}

	err = writer.Write(&clients.Response{Host: "example.com-very-long-host-to-force-buffer-flush", Port: "443"})
	require.Error(t, err)
}
