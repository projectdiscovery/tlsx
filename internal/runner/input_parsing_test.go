package runner

import (
	"strings"
	"testing"

	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
)

func TestEnqueueLine(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: []string{},
		},
		{
			name:     "whitespace only",
			input:    "   \t\n  ",
			expected: []string{},
		},
		{
			name:     "single host",
			input:    "example.com",
			expected: []string{"example.com"},
		},
		{
			name:     "single host with whitespace",
			input:    "  example.com  ",
			expected: []string{"example.com"},
		},
		{
			name:     "two hosts comma separated",
			input:    "example.com,google.com",
			expected: []string{"example.com", "google.com"},
		},
		{
			name:     "hosts with spaces around commas",
			input:    "example.com , google.com , github.com",
			expected: []string{"example.com", "google.com", "github.com"},
		},
		{
			name:     "trailing comma",
			input:    "example.com,google.com,",
			expected: []string{"example.com", "google.com"},
		},
		{
			name:     "leading comma",
			input:    ",example.com,google.com",
			expected: []string{"example.com", "google.com"},
		},
		{
			name:     "multiple consecutive commas",
			input:    "example.com,,,google.com",
			expected: []string{"example.com", "google.com"},
		},
		{
			name:     "only commas",
			input:    ",,,",
			expected: []string{},
		},
		{
			name:     "mixed whitespace and commas",
			input:    " , example.com , , google.com , ",
			expected: []string{"example.com", "google.com"},
		},
		{
			name:     "CRLF line ending",
			input:    "example.com,google.com\r\n",
			expected: []string{"example.com", "google.com"},
		},
		{
			name:     "tabs and mixed whitespace",
			input:    "\texample.com\t,\tgoogle.com\t",
			expected: []string{"example.com", "google.com"},
		},
		{
			name:     "IP addresses",
			input:    "192.168.1.1,10.0.0.1,127.0.0.1",
			expected: []string{"192.168.1.1", "10.0.0.1", "127.0.0.1"},
		},
		{
			name:     "simple comma-separated hosts",
			input:    "host1.com,host2.org,host3.net",
			expected: []string{"host1.com", "host2.org", "host3.net"},
		},
		{
			name:     "very long line with many hosts",
			input:    strings.Repeat("host", 100) + ".com," + strings.Repeat("test", 100) + ".org",
			expected: []string{strings.Repeat("host", 100) + ".com", strings.Repeat("test", 100) + ".org"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a properly initialized runner with minimal required fields
			runner := &Runner{
				options: &clients.Options{
					Ports: []string{"443"}, // Default port to prevent nil pointer
				},
			}
			
			// Channel to collect processed inputs with larger buffer for CIDR expansion
			inputs := make(chan taskInput, 1000)
			
			// Process the line
			runner.enqueueLine(tt.input, inputs)
			close(inputs)
			
			// Collect results
			var results []string
			for input := range inputs {
				results = append(results, input.host)
			}
			
			// Verify results
			if len(results) != len(tt.expected) {
				t.Errorf("Expected %d results, got %d", len(tt.expected), len(results))
				t.Errorf("Expected: %v", tt.expected)
				t.Errorf("Got: %v", results)
				return
			}
			
			for i, expected := range tt.expected {
				if results[i] != expected {
					t.Errorf("Expected result[%d] = %q, got %q", i, expected, results[i])
				}
			}
		})
	}
}

func TestInputConsistency(t *testing.T) {
	// Test that -u, -l, and stdin all produce the same results
	testInput := "example.com , google.com,  , github.com,  "
	expected := []string{"example.com", "google.com", "github.com"}
	
	t.Run("consistency across input methods", func(t *testing.T) {
		runner := &Runner{
			options: &clients.Options{
				Ports: []string{"443"},
			},
		}
		
		// Test enqueueLine directly (used by all input methods)
		inputs := make(chan taskInput, 100)
		runner.enqueueLine(testInput, inputs)
		close(inputs)
		
		var results []string
		for input := range inputs {
			results = append(results, input.host)
		}
		
		if len(results) != len(expected) {
			t.Errorf("Expected %d results, got %d", len(expected), len(results))
			return
		}
		
		for i, exp := range expected {
			if results[i] != exp {
				t.Errorf("Expected result[%d] = %q, got %q", i, exp, results[i])
			}
		}
	})
}

func TestLargeInputHandling(t *testing.T) {
	t.Run("large CSV line", func(t *testing.T) {
		// Create a line with 10,000 hosts
		var hosts []string
		for i := 0; i < 10000; i++ {
			hosts = append(hosts, "host"+string(rune('0'+i%10))+".example.com")
		}
		largeInput := strings.Join(hosts, ",")
		
		runner := &Runner{
			options: &clients.Options{
				Ports: []string{"443"},
			},
		}
		inputs := make(chan taskInput, 20000)
		
		runner.enqueueLine(largeInput, inputs)
		close(inputs)
		
		count := 0
		for range inputs {
			count++
		}
		
		if count != 10000 {
			t.Errorf("Expected 10000 hosts, got %d", count)
		}
	})
}

func TestMalformedInputs(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int // number of valid hosts expected
	}{
		{
			name:     "unicode characters",
			input:    "例え.com,тест.org,مثال.net",
			expected: 3,
		},
		{
			name:     "special characters in hostnames",
			input:    "sub-domain.example.com,under_score.test.org",
			expected: 2,
		},
		{
			name:     "mixed valid and empty",
			input:    "valid.com,,, ,another.com,",
			expected: 2,
		},
		{
			name:     "extremely long hostname",
			input:    strings.Repeat("a", 253) + ".com",
			expected: 1,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &Runner{
			options: &clients.Options{
				Ports: []string{"443"},
			},
		}
			inputs := make(chan taskInput, 100)
			
			runner.enqueueLine(tt.input, inputs)
			close(inputs)
			
			count := 0
			for range inputs {
				count++
			}
			
			if count != tt.expected {
				t.Errorf("Expected %d valid hosts, got %d", tt.expected, count)
			}
		})
	}
}

func TestMemoryEfficiency(t *testing.T) {
	t.Run("no memory leaks with large inputs", func(t *testing.T) {
		runner := &Runner{
			options: &clients.Options{
				Ports: []string{"443"},
			},
		}
		
		// Process many large lines to check for memory leaks
		for i := 0; i < 100; i++ {
			largeInput := strings.Repeat("host.com,", 1000)
			inputs := make(chan taskInput, 2000)
			
			runner.enqueueLine(largeInput, inputs)
			close(inputs)
			
			// Drain the channel
			for range inputs {
			}
		}
		// If we get here without OOM, memory handling is reasonable
	})
}

func TestConcurrentAccess(t *testing.T) {
	t.Run("concurrent enqueueLine calls", func(t *testing.T) {
		runner := &Runner{
			options: &clients.Options{
				Ports: []string{"443"},
			},
		}
		inputs := make(chan taskInput, 1000)
		
		// Launch multiple goroutines
		done := make(chan bool, 10)
		for i := 0; i < 10; i++ {
			go func(id int) {
				testInput := "host" + string(rune('0'+id)) + ".com,test" + string(rune('0'+id)) + ".org"
				runner.enqueueLine(testInput, inputs)
				done <- true
			}(i)
		}
		
		// Wait for all goroutines
		for i := 0; i < 10; i++ {
			<-done
		}
		close(inputs)
		
		// Count results
		count := 0
		for range inputs {
			count++
		}
		
		if count != 20 { // 10 goroutines * 2 hosts each
			t.Errorf("Expected 20 hosts, got %d", count)
		}
	})
}

// Benchmark tests for performance validation
func BenchmarkEnqueueLine(b *testing.B) {
	runner := &Runner{
		options: &clients.Options{Ports: []string{"443"}},
	}
	inputs := make(chan taskInput, 1000)
	testInput := "example.com,google.com,github.com,stackoverflow.com,reddit.com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runner.enqueueLine(testInput, inputs)
		// Drain channel fully to prevent saturation
		for len(inputs) > 0 {
			<-inputs
		}
	}
}

func BenchmarkEnqueueLineLarge(b *testing.B) {
	runner := &Runner{
		options: &clients.Options{Ports: []string{"443"}},
	}
	inputs := make(chan taskInput, 10000)
	
	// Create a line with 1000 hosts
	var hosts []string
	for i := 0; i < 1000; i++ {
		hosts = append(hosts, "host"+string(rune('0'+i%10))+".example.com")
	}
	largeInput := strings.Join(hosts, ",")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runner.enqueueLine(largeInput, inputs)
		// Drain channel
		for len(inputs) > 0 {
			<-inputs
		}
	}
}
