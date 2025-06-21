package main

import (
	"os"
	"testing"

	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCTLogsModeValidation(t *testing.T) {
	// Save original stdin
	originalStdin := os.Stdin
	defer func() {
		os.Stdin = originalStdin
	}()

	tests := []struct {
		name        string
		inputs      []string
		inputList   string
		hasStdin    bool
		ctLogs      bool
		expectError bool
		errorMsg    string
	}{
		{
			name:        "CT logs mode with host input should fail",
			inputs:      []string{"example.com"},
			ctLogs:      true,
			expectError: true,
			errorMsg:    "CT logs mode (-ctl) and input mode (-u/-l/stdin) cannot be used together",
		},
		{
			name:        "CT logs mode with input list should fail",
			inputList:   "hosts.txt",
			ctLogs:      true,
			expectError: true,
			errorMsg:    "CT logs mode (-ctl) and input mode (-u/-l/stdin) cannot be used together",
		},
		{
			name:        "CT logs mode with stdin should fail",
			hasStdin:    true,
			ctLogs:      true,
			expectError: true,
			errorMsg:    "CT logs mode (-ctl) and input mode (-u/-l/stdin) cannot be used together",
		},
		{
			name:        "CT logs mode without input should succeed",
			ctLogs:      true,
			expectError: false,
		},
		{
			name:        "No CT logs mode with input should succeed",
			inputs:      []string{"example.com"},
			ctLogs:      false,
			expectError: false,
		},
		{
			name:        "No CT logs mode without input should enable CT logs by default",
			ctLogs:      false,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset options for each test
			options = &clients.Options{
				Inputs:    tt.inputs,
				InputList: tt.inputList,
				CTLogs:    tt.ctLogs,
			}

			// Mock stdin if needed
			if tt.hasStdin {
				// Create a temporary file to simulate stdin with data
				tmpFile, err := os.CreateTemp("", "stdin_test")
				require.NoError(t, err)
				defer os.Remove(tmpFile.Name())

				_, err = tmpFile.WriteString("test input")
				require.NoError(t, err)
				tmpFile.Close()

				// Reopen for reading
				tmpFile, err = os.Open(tmpFile.Name())
				require.NoError(t, err)
				defer tmpFile.Close()

				os.Stdin = tmpFile
			} else {
				// Use a pipe to simulate empty stdin
				r, w, err := os.Pipe()
				require.NoError(t, err)
				defer r.Close()
				defer w.Close()

				os.Stdin = r
			}

			err := readFlags()

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)

				// Check if CT logs mode was enabled by default when no input was provided
				if len(tt.inputs) == 0 && tt.inputList == "" && !tt.hasStdin && !tt.ctLogs {
					assert.True(t, options.CTLogs, "CT logs mode should be enabled by default when no input is provided")
					assert.True(t, options.SAN, "SAN should be enabled by default when CT logs mode is active")
				}
			}
		})
	}
}

func TestSANDefaultInCTLogsMode(t *testing.T) {
	tests := []struct {
		name           string
		ctLogs         bool
		initialSAN     bool
		expectedSAN    bool
		expectedCTLogs bool
	}{
		{
			name:           "CT logs mode should enable SAN by default",
			ctLogs:         true,
			initialSAN:     false,
			expectedSAN:    true,
			expectedCTLogs: true,
		},
		{
			name:           "CT logs mode should respect explicit SAN setting",
			ctLogs:         true,
			initialSAN:     true,
			expectedSAN:    true,
			expectedCTLogs: true,
		},
		{
			name:           "Non-CT logs mode should not change SAN",
			ctLogs:         false,
			initialSAN:     false,
			expectedSAN:    false,
			expectedCTLogs: true, // Will be enabled by default when no input
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset options
			options = &clients.Options{
				CTLogs: tt.ctLogs,
				SAN:    tt.initialSAN,
			}

			// Mock empty stdin
			r, w, err := os.Pipe()
			require.NoError(t, err)
			defer r.Close()
			defer w.Close()
			os.Stdin = r

			err = readFlags()
			require.NoError(t, err)

			assert.Equal(t, tt.expectedCTLogs, options.CTLogs)
			assert.Equal(t, tt.expectedSAN, options.SAN)
		})
	}
}

func TestStdinDetection(t *testing.T) {
	// Save original stdin
	originalStdin := os.Stdin
	defer func() {
		os.Stdin = originalStdin
	}()

	tests := []struct {
		name        string
		setupStdin  func() error
		expectStdin bool
	}{
		{
			name: "Empty stdin should not be detected",
			setupStdin: func() error {
				r, w, err := os.Pipe()
				if err != nil {
					return err
				}
				w.Close()
				os.Stdin = r
				return nil
			},
			expectStdin: false,
		},
		{
			name: "Stdin with data should be detected",
			setupStdin: func() error {
				tmpFile, err := os.CreateTemp("", "stdin_test")
				if err != nil {
					return err
				}

				_, err = tmpFile.WriteString("test data")
				if err != nil {
					return err
				}
				tmpFile.Close()

				tmpFile, err = os.Open(tmpFile.Name())
				if err != nil {
					return err
				}

				os.Stdin = tmpFile
				return nil
			},
			expectStdin: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.setupStdin()
			require.NoError(t, err)

			// Reset options
			options = &clients.Options{}

			err = readFlags()
			require.NoError(t, err)

			// If stdin was detected, CT logs mode should not be enabled by default
			if tt.expectStdin {
				assert.False(t, options.CTLogs, "CT logs mode should not be enabled when stdin has data")
			} else {
				assert.True(t, options.CTLogs, "CT logs mode should be enabled when no input is provided")
			}
		})
	}
}
