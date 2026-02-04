package output

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileWriterPeriodicFlush(t *testing.T) {
	// Create temp file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_output.jsonl")

	// Create writer
	writer, err := newFileOutputWriter(tmpFile)
	require.NoError(t, err)
	defer writer.Close()

	// Write exactly flushThreshold entries
	for i := 0; i < flushThreshold; i++ {
		err := writer.Write([]byte(`{"test": "data"}`))
		require.NoError(t, err)
	}

	// After flushThreshold writes, data should be flushed to disk
	// Read file contents without closing writer
	contents, err := os.ReadFile(tmpFile)
	require.NoError(t, err)

	// File should have content (periodic flush worked)
	assert.NotEmpty(t, contents, "file should have content after %d writes due to periodic flush", flushThreshold)
}

func TestFileWriterWriteCount(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_count.jsonl")

	writer, err := newFileOutputWriter(tmpFile)
	require.NoError(t, err)
	defer writer.Close()

	// Write some entries
	for i := 0; i < 50; i++ {
		err := writer.Write([]byte(`{"count": 1}`))
		require.NoError(t, err)
	}

	// Verify write count is tracked
	count := writer.writeCount.Load()
	assert.Equal(t, int64(50), count, "write count should be 50")
}

func TestFileWriterCloseFlushes(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_close.jsonl")

	writer, err := newFileOutputWriter(tmpFile)
	require.NoError(t, err)

	// Write less than flushThreshold (so periodic flush won't trigger)
	for i := 0; i < flushThreshold/2; i++ {
		err := writer.Write([]byte(`{"close": "test"}`))
		require.NoError(t, err)
	}

	// Close should flush remaining data
	err = writer.Close()
	require.NoError(t, err)

	// Verify all data was written
	contents, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	assert.NotEmpty(t, contents, "file should have content after close")
}
