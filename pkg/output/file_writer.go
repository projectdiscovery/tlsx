package output

import (
	"bufio"
	"os"
	"sync"
)

// fileWriter is a concurrent file based output writer.
type fileWriter struct {
	file   *os.File
	writer *bufio.Writer
	mu     sync.Mutex
}

// NewFileOutputWriter creates a new buffered writer for a file
func newFileOutputWriter(file string) (*fileWriter, error) {
	output, err := os.Create(file)
	if err != nil {
		return nil, err
	}
	return &fileWriter{file: output, writer: bufio.NewWriter(output)}, nil
}

// WriteString writes an output to the underlying file
func (w *fileWriter) Write(data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	
	_, err := w.writer.Write(data)
	if err != nil {
		return err
	}
	_, err = w.writer.WriteRune('\n')
	if err != nil {
		return err
	}
	
	// Flush periodically to prevent buffer deadlock in long-running scans
	// This fixes issue #819 where tlsx hangs after ~25k targets
	err = w.writer.Flush()
	if err != nil {
		return err
	}
	
	// Sync to disk to prevent data loss on crash
	//nolint:errcheck // we don't care whether sync failed or succeeded.
	w.file.Sync()
	
	return nil
}

// Close closes the underlying writer flushing everything to disk
func (w *fileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	
	if err := w.writer.Flush(); err != nil {
		return err
	}
	//nolint:errcheck // we don't care whether sync failed or succeeded.
	w.file.Sync()
	return w.file.Close()
}
