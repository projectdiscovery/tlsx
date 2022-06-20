package runner

import (
	"bufio"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/tlsx/pkg/output"
	"github.com/projectdiscovery/tlsx/pkg/output/stats"
	"github.com/projectdiscovery/tlsx/pkg/tlsx"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
)

// Runner is a client for running the enumeration process
type Runner struct {
	hasStdin     bool
	outputWriter output.Writer
	tlsxService  *tlsx.Service
	options      *clients.Options
}

// New creates a new runner from provided configuration options
func New(options *clients.Options) (*Runner, error) {
	showBanner()

	if options.Version {
		gologger.Info().Msgf("Current version: %s", version)
		return nil, nil
	}
	runner := &Runner{options: options}
	if err := runner.validateOptions(); err != nil {
		return nil, errors.Wrap(err, "could not validate options")
	}

	outputWriter, err := output.New(options.JSON, options.OutputFile)
	if err != nil {
		return nil, errors.Wrap(err, "could not create output writer")
	}
	runner.outputWriter = outputWriter

	tlsxService, err := tlsx.New(options)
	if err != nil {
		return nil, errors.Wrap(err, "could not create tlsx client")
	}
	runner.tlsxService = tlsxService
	return runner, nil
}

// Close closes the runner releasing resources
func (r *Runner) Close() error {
	return r.outputWriter.Close()
}

type taskInput struct {
	host string
	port string
}

func (t taskInput) Address() string {
	return net.JoinHostPort(t.host, t.port)
}

// Execute executes the main data collection loop
func (r *Runner) Execute() error {
	// Create the worker goroutines for processing
	inputs := make(chan taskInput, r.options.Concurrency)
	wg := &sync.WaitGroup{}

	for i := 0; i < r.options.Concurrency; i++ {
		wg.Add(1)
		go r.processInputElementWorker(inputs, wg)
	}
	// Queue inputs
	r.normalizeAndQueueInputs(inputs)

	close(inputs)
	wg.Wait()

	// Print the stats if auto fallback mode is used
	if r.options.ScanMode == "auto" {
		gologger.Info().Msgf("Connections made using crypto/tls: %d", stats.LoadCryptoTLSConnections())
		gologger.Info().Msgf("Connections made using zcrypto/tls: %d", stats.LoadZcryptoTLSConnections())
	}
	return nil
}

// processInputElementWorker processes an element from input
func (r *Runner) processInputElementWorker(inputs chan taskInput, wg *sync.WaitGroup) {
	defer wg.Done()

	for task := range inputs {
		response, err := r.tlsxService.Connect(task.host, task.port)
		if err != nil {
			gologger.Warning().Msgf("Could not connect input %s: %s", task.Address(), err)
			return
		}
		if response != nil {
			if err := r.outputWriter.Write(response); err != nil {
				gologger.Warning().Msgf("Could not write output %s: %s", task.Address(), err)
			}
		}
	}
}

// normalizeAndQueueInputs normalizes the inputs and queues them for execution
func (r *Runner) normalizeAndQueueInputs(inputs chan taskInput) error {
	// Process Normal Inputs
	for _, text := range r.options.Inputs {
		r.processInputItem(text, inputs)
	}

	if r.options.InputList != "" {
		file, err := os.Open(r.options.InputList)
		if err != nil {
			return errors.Wrap(err, "could not open input file")
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			text := scanner.Text()
			if text != "" {
				r.processInputItem(text, inputs)
			}
		}
	}
	if r.hasStdin {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			text := scanner.Text()
			if text != "" {
				r.processInputItem(text, inputs)
			}
		}
	}
	return nil
}

// processInputItem processes a single input item
func (r *Runner) processInputItem(input string, inputs chan taskInput) {
	// CIDR input
	if _, ipRange, _ := net.ParseCIDR(input); ipRange != nil {
		cidrInputs, err := mapcidr.IPAddressesAsStream(input)
		if err != nil {
			gologger.Error().Msgf("Could not parse cidr %s: %s", input, err)
			return
		}
		for cidr := range cidrInputs {
			for _, port := range r.options.Ports {
				inputs <- taskInput{host: cidr, port: port}
			}
		}
	} else {
		// Normal input
		host, customPort := r.getHostPortFromInput(input)
		if customPort == "" {
			for _, port := range r.options.Ports {
				inputs <- taskInput{host: host, port: port}
			}
		} else {
			inputs <- taskInput{host: host, port: customPort}
		}
	}
}

// getHostPortFromInput returns host and optionally port from input.
// If no ports are found, port field is left blank and user specified ports
// are used.
func (r *Runner) getHostPortFromInput(input string) (string, string) {
	host := input

	if strings.Contains(input, "://") {
		if parsed, err := url.Parse(input); err != nil {
			return "", ""
		} else {
			host = parsed.Host
		}
	}
	if strings.Contains(host, ":") {
		if host, port, err := net.SplitHostPort(host); err != nil {
			return "", ""
		} else {
			return host, port
		}
	}
	return host, ""
}
