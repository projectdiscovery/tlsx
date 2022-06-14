package runner

import (
	"bufio"
	"os"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/tlsx/pkg/output"
	"github.com/projectdiscovery/tlsx/pkg/tlsx"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/remeh/sizedwaitgroup"
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

	runner := &Runner{options: options}
	if err := runner.validateOptions(); err != nil {
		return nil, errors.Wrap(err, "could not validate options")
	}

	outputWriter, err := output.New(options.OutputFile)
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

// Execute executes the main data collection loop
func (r *Runner) Execute() error {
	swg := sizedwaitgroup.New(r.options.Concurrency)

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
				swg.Add()
				go r.processInputElement(text, &swg)
			}
		}
	}
	if r.hasStdin {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			text := scanner.Text()
			if text != "" {
				swg.Add()
				go r.processInputElement(text, &swg)
			}
		}
	}
	for _, text := range r.options.Inputs {
		swg.Add()
		go r.processInputElement(text, &swg)
	}
	swg.Wait()
	return nil
}

// processInputElement processes an element from input
func (r *Runner) processInputElement(input string, swg *sizedwaitgroup.SizedWaitGroup) {
	defer swg.Done()

	response, err := r.tlsxService.Connect(input)
	if err != nil {
		gologger.Warning().Msgf("Could not connect input %s: %s", input, err)
		return
	}
	if response != nil {
		if err := r.outputWriter.Write(response); err != nil {
			gologger.Warning().Msgf("Could not write output %s: %s", input, err)
		}
	}
}
