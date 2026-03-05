package output

import (
	"os"
	"testing"
)

func TestFileWriterConcurrent(t *testing.T) {
	// Create temporary file
	tmpfile, err := os.CreateTemp("", "test-*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	
	writer, err := newFileOutputWriter(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	
	// Test concurrent writes
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				data := []byte(`{"test": "data"}`)
				if err := writer.Write(data); err != nil {
					t.Errorf("Write failed: %v", err)
					return
				}
			}
			done <- true
		}(i)
	}
	
	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
	
	// Verify file was written
	info, err := tmpfile.Stat()
	if err != nil {
		t.Fatal(err)
	}
	
	if info.Size() == 0 {
		t.Error("Expected file to have content")
	}
}

func TestFileWriterFlush(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test-flush-*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	
	writer, err := newFileOutputWriter(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}
	
	// Write data
	data := []byte(`{"test": "flush"}`)
	if err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	
	// Data should be flushed to disk
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	
	// Read file and verify
	content, err := os.ReadFile(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}
	
	expected := `{"test": "flush"}` + "\n"
	if string(content) != expected {
		t.Errorf("Expected %q, got %q", expected, string(content))
	}
}
