package output

import (
	"os"
	"regexp"
	"sync"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
)

// Writer is an interface which writes output to somewhere for katana events.
type Writer interface {
	// Close closes the output writer interface
	Close() error
	// Write writes the event to file and/or screen.
	Write(*clients.Response) error
}

var decolorizerRegex = regexp.MustCompile(`\x1B\[[0-9;]*[a-zA-Z]`)

// StandardWriter is an standard output writer structure
type StandardWriter struct {
	json        bool
	outputFile  *fileWriter
	outputMutex *sync.Mutex
}

// New returns a new output writer instance
func New(file string) (Writer, error) {
	var outputFile *fileWriter
	if file != "" {
		output, err := newFileOutputWriter(file)
		if err != nil {
			return nil, errors.Wrap(err, "could not create output file")
		}
		outputFile = output
	}
	writer := &StandardWriter{
		outputFile:  outputFile,
		outputMutex: &sync.Mutex{},
	}
	return writer, nil
}

// Write writes the event to file and/or screen.
func (w *StandardWriter) Write(event *clients.Response) error {
	data, err := w.formatJSON(event)
	if err != nil {
		return errors.Wrap(err, "could not format output")
	}
	w.outputMutex.Lock()
	defer w.outputMutex.Unlock()

	_, _ = os.Stdout.Write(data)
	_, _ = os.Stdout.Write([]byte("\n"))
	if w.outputFile != nil {
		if !w.json {
			data = decolorizerRegex.ReplaceAll(data, []byte(""))
		}
		if writeErr := w.outputFile.Write(data); writeErr != nil {
			return errors.Wrap(err, "could not write to output")
		}
	}
	return nil
}

// Close closes the output writer
func (w *StandardWriter) Close() error {
	var err error
	if w.outputFile != nil {
		err = w.outputFile.Close()
	}
	return err
}

// formatJSON formats the output for json based formatting
func (w *StandardWriter) formatJSON(output *clients.Response) ([]byte, error) {
	return jsoniter.Marshal(output)
}
