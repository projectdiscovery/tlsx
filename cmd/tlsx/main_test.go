package main

import (
	"testing"

	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCTLogsModeValidation(t *testing.T) {
	// Save original options
	originalOptions := options
	defer func() {
		options = originalOptions
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset options for each test
			options = &clients.Options{
				CTLogs: tt.ctLogs,
			}

			// Build test arguments
			var args []string
			if len(tt.inputs) > 0 {
				for _, input := range tt.inputs {
					args = append(args, "-u", input)
				}
			}
			if tt.inputList != "" {
				args = append(args, "-l", tt.inputList)
			}
			if tt.ctLogs {
				args = append(args, "-ctl")
			}

			err := readFlags(args...)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestFlagParsingWithTestFlags(t *testing.T) {
	// Save original options
	originalOptions := options
	defer func() {
		options = originalOptions
	}()

	// Reset options
	options = &clients.Options{}

	// Test that empty args work (simulating test environment)
	err := readFlags()
	require.NoError(t, err)

	// Test that CT logs mode is enabled by default when no input is provided
	assert.True(t, options.CTLogs, "CT logs mode should be enabled by default when no input is provided")
	assert.True(t, options.SAN, "SAN should be enabled by default when CT logs mode is active")
}
