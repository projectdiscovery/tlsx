package runner

import (
	"os"
	"strings"
	"testing"

	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
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
