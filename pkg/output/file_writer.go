package output

import (
	"bufio"
	"os"
)

// fileWriter is a concurrent file based output writer.
type fileWriter struct {
	file   *os.File
	writer *bufio.Writer
}

// newFileOutputWriter creates a new buffered writer for a file
func newFileOutputWriter(file string) (*fileWriter, error) {
	output, err := os.Create(file)
	if err != nil {
		return nil, err
	}
	return &fileWriter{file: output, writer: bufio.NewWriter(output)}, nil
}

// Write writes an output to the underlying file
func (w *fileWriter) Write(data []byte) error {
	_, err := w.writer.Write(data)
	if err != nil {
		return err
	}
	_, err = w.writer.WriteRune('\n')
	return err
}

// Close closes the underlying writer flushing everything to disk.
// The file is always closed even when Flush fails, preventing fd leaks.
func (w *fileWriter) Close() error {
	flushErr := w.writer.Flush()
	//nolint:errcheck // we don't care whether sync failed or succeeded.
	w.file.Sync()
	closeErr := w.file.Close()
	if flushErr != nil {
		return flushErr
	}
	return closeErr
}
