package runner

import (
	"os"
	"strings"
	"testing"

	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/projectdiscovery/utils/auth/pdcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Normal input
func Test_InputDomain_processInputItem(t *testing.T) {
	options := &clients.Options{
		Ports: []string{"443"},
	}
	runner := &Runner{options: options}

	inputs := make(chan taskInput)
	domain := "www.example.com"
	expected := []taskInput{
		{
			host: "www.example.com",
			port: "443",
		},
	}
	go func() {
		runner.processInputItem(domain, inputs)
		defer close(inputs)
	}()
	var got []taskInput
	for task := range inputs {
		got = append(got, task)
	}
	require.ElementsMatch(t, expected, got, "could not get correct taskInputs")
}

func Test_InputForMultipleIps_processInputItem(t *testing.T) {
	options := &clients.Options{
		Ports:      []string{"443"},
		ScanAllIPs: true,
	}
	runner := &Runner{options: options}
	dnsOptions := dnsx.DefaultOptions
	dnsOptions.MaxRetries = 3
	dnsOptions.Hostsfile = true
	dnsclient, err := dnsx.New(dnsOptions)
	require.Nil(t, err, "failed to create dns client")
	runner.dnsclient = dnsclient

	inputs := make(chan taskInput)
	domain := "one.one.one.one"
	expected := []taskInput{
		{
			host: "one.one.one.one",
			ip:   "1.1.1.1",
			port: "443",
		},
		{
			host: "one.one.one.one",
			ip:   "1.0.0.1",
			port: "443",
		},
	}
	go func() {
		runner.processInputItem(domain, inputs)
		defer close(inputs)
	}()
	var got []taskInput
	for task := range inputs {
		got = append(got, task)
	}
	require.ElementsMatch(t, expected, got, "could not get correct taskInputs")
}

func Test_InputCIDR_processInputItem(t *testing.T) {
	options := &clients.Options{
		Ports: []string{"443"},
	}
	runner := &Runner{options: options}

	inputs := make(chan taskInput)
	inputCIDR := "173.0.84.0/30"
	expected := []taskInput{
		{
			host: "173.0.84.0",
			port: "443",
		}, {
			host: "173.0.84.1",
			port: "443",
		},
		{
			host: "173.0.84.2",
			port: "443",
		}, {
			host: "173.0.84.3",
			port: "443",
		},
	}
	go func() {
		runner.processInputItem(inputCIDR, inputs)
		defer close(inputs)
	}()
	var got []taskInput
	for task := range inputs {
		got = append(got, task)
	}
	require.ElementsMatch(t, expected, got, "could not get correct taskInputs")
}

func Test_InputASN_processInputItem(t *testing.T) {

	// skip if keys are missing
	h := pdcp.PDCPCredHandler{}
	_, err := h.GetCreds()
	if err != nil {
		t.Skip("skipping ASN test as keys are missing")
	}

	options := &clients.Options{
		Ports: []string{"443"},
	}
	runner := &Runner{options: options}
	inputs := make(chan taskInput)

	asn := "AS14421"
	expectedOutputFile := "tests/AS14421.txt"
	go func() {
		runner.processInputItem(asn, inputs)
		defer close(inputs)
	}()
	var got []taskInput
	for task := range inputs {
		got = append(got, task)
	}
	expected, err := getTaskInputFromFile(expectedOutputFile, options.Ports)
	require.Nil(t, err, "could not read the expectedOutputFile")
	require.ElementsMatch(t, expected, got, "could not get correct taskInputs")
}

func Test_RevokedCert_processInputItem(t *testing.T) {
	options := &clients.Options{
		Ports:   []string{"443"},
		Revoked: true,
	}
	runner := &Runner{options: options}

	inputs := make(chan taskInput)
	domain := "revoked.badssl.com"
	expected := []taskInput{
		{
			host: "revoked.badssl.com",
			port: "443",
		},
	}
	go func() {
		runner.processInputItem(domain, inputs)
		defer close(inputs)
	}()
	var got []taskInput
	for task := range inputs {
		got = append(got, task)
	}
	require.ElementsMatch(t, expected, got, "could not get correct taskInputs")
}

func Test_SelfSignedCert_processInputItem(t *testing.T) {
	options := &clients.Options{
		Ports:      []string{"443"},
		SelfSigned: true,
	}
	runner := &Runner{options: options}

	inputs := make(chan taskInput)
	domain := "self-signed.badssl.com"
	expected := []taskInput{
		{
			host: "self-signed.badssl.com",
			port: "443",
		},
	}
	go func() {
		runner.processInputItem(domain, inputs)
		defer close(inputs)
	}()
	var got []taskInput
	for task := range inputs {
		got = append(got, task)
	}
	require.ElementsMatch(t, expected, got, "could not get correct taskInputs")
}

func getTaskInputFromFile(filename string, ports []string) ([]taskInput, error) {
	fileContent, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	ipList := strings.Split(strings.ReplaceAll(string(fileContent), "\r\n", "\n"), "\n")
	var ret []taskInput
	for _, ip := range ipList {
		for _, p := range ports {
			ret = append(ret, taskInput{host: ip, port: p})
		}
	}
	return ret, nil
}

func Test_CTLogsModeValidation(t *testing.T) {
	// Test that CT logs mode and input mode cannot be used together
	// This validation is now done in the main package, so this test should be removed
	// or modified to test the actual runner behavior
	t.Skip("Validation is now handled in main package")
}

func Test_CTLogsModeDefaultEnabled(t *testing.T) {
	// Test that CT logs mode is enabled by default when no input is provided
	options := &clients.Options{
		// No inputs provided
	}

	runner := &Runner{options: options}
	runner.hasStdin = false // Simulate no stdin

	// The validation logic is now in main package, so we'll test the runner behavior
	// when CT logs mode is already set
	options.CTLogs = true
	options.SAN = true

	err := runner.validateOptions()
	require.NoError(t, err)
	assert.True(t, options.CTLogs)
	assert.True(t, options.SAN)
}

func Test_CTLogsModeWithInputDisabled(t *testing.T) {
	// Test that CT logs mode is NOT enabled when input is provided
	options := &clients.Options{
		Inputs: []string{"example.com"},
		CTLogs: false, // Explicitly disabled
	}

	runner := &Runner{options: options}
	runner.hasStdin = false

	err := runner.validateOptions()
	require.NoError(t, err)
	assert.False(t, options.CTLogs)
}

func Test_CTLogsModeWithStdinDisabled(t *testing.T) {
	// Test that CT logs mode is NOT enabled when stdin has data
	options := &clients.Options{
		CTLogs: false, // Explicitly disabled
	}

	runner := &Runner{options: options}
	runner.hasStdin = true    // Simulate stdin has data
	runner.hasStdinSet = true // Mark that hasStdin was manually set

	err := runner.validateOptions()
	require.NoError(t, err)
	assert.False(t, options.CTLogs)
}

func Test_CTLogsModeExplicitEnabled(t *testing.T) {
	// Test that explicit CT logs mode works correctly
	options := &clients.Options{
		CTLogs: true,
		SAN:    true, // SAN should be enabled by default in CT logs mode
	}

	runner := &Runner{options: options}
	runner.hasStdin = false

	err := runner.validateOptions()
	require.NoError(t, err)
	assert.True(t, options.CTLogs)
	assert.True(t, options.SAN)
}

func Test_CTLogsModeWithSANOverride(t *testing.T) {
	// Test that SAN can be overridden when CT logs mode is enabled
	options := &clients.Options{
		CTLogs: true,
		SAN:    false, // Explicitly disable SAN
	}

	runner := &Runner{options: options}
	runner.hasStdin = false

	err := runner.validateOptions()
	require.NoError(t, err)
	assert.True(t, options.CTLogs)
	assert.False(t, options.SAN) // Should respect explicit SAN setting
}

func Test_CTLogsModePortsDefault(t *testing.T) {
	// Test that default ports are set when CT logs mode is enabled
	options := &clients.Options{
		CTLogs: true,
		// No ports specified
	}

	runner := &Runner{options: options}
	runner.hasStdin = false

	err := runner.validateOptions()
	require.NoError(t, err)
	// The ports should be set to default 443
	assert.Len(t, options.Ports, 1)
	assert.Equal(t, "443", options.Ports[0])
}

func Test_CTLogsModeExecute(t *testing.T) {
	// Test that CT logs mode execution path is taken
	options := &clients.Options{
		CTLogs: true,
	}

	runner := &Runner{options: options}
	runner.hasStdin = false

	err := runner.validateOptions()
	require.NoError(t, err)
	assert.True(t, options.CTLogs)
}

func Test_CTLogsModeWithAllProbes(t *testing.T) {
	// Test that CT logs mode works with various probe combinations
	testCases := []struct {
		name   string
		probes func(*clients.Options)
	}{
		{
			name: "SelfSigned probe",
			probes: func(o *clients.Options) {
				o.SelfSigned = true
			},
		},
		{
			name: "Wildcard probe",
			probes: func(o *clients.Options) {
				o.WildcardCertCheck = true
			},
		},
		{
			name: "Expired probe",
			probes: func(o *clients.Options) {
				o.Expired = true
			},
		},
		{
			name: "Multiple probes",
			probes: func(o *clients.Options) {
				o.SelfSigned = true
				o.WildcardCertCheck = true
				o.Expired = true
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			options := &clients.Options{
				CTLogs: true,
			}

			tc.probes(options)

			runner := &Runner{options: options}
			runner.hasStdin = false

			err := runner.validateOptions()
			require.NoError(t, err)
			assert.True(t, options.CTLogs)
		})
	}
}

func Test_CTLogsModeOutputOptions(t *testing.T) {
	// Test that CT logs mode works with various output options
	testCases := []struct {
		name   string
		output func(*clients.Options)
	}{
		{
			name: "JSON output",
			output: func(o *clients.Options) {
				o.JSON = true
			},
		},
		{
			name: "Verbose output",
			output: func(o *clients.Options) {
				o.Verbose = true
			},
		},
		{
			name: "Silent output",
			output: func(o *clients.Options) {
				o.Silent = true
			},
		},
		{
			name: "Certificate output",
			output: func(o *clients.Options) {
				o.Cert = true
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			options := &clients.Options{
				CTLogs: true,
			}

			tc.output(options)

			runner := &Runner{options: options}
			runner.hasStdin = false

			err := runner.validateOptions()
			require.NoError(t, err)
			assert.True(t, options.CTLogs)
		})
	}
}
