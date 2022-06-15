package main

import (
	"github.com/pkg/errors"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/tlsx/internal/runner"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
)

var (
	cfgFile string
	options = &clients.Options{}
)

func main() {
	if err := process(); err != nil {
		gologger.Fatal().Msgf("Could not process: %s", err)
	}
}

func process() error {
	if err := readFlags(); err != nil {
		return errors.Wrap(err, "could not read flags")
	}
	runner, err := runner.New(options)
	if err != nil {
		return errors.Wrap(err, "could not create runner")
	}
	if runner == nil {
		return nil
	}
	if err := runner.Execute(); err != nil {
		return errors.Wrap(err, "could not execute runner")
	}
	if err := runner.Close(); err != nil {
		return errors.Wrap(err, "could not close runner")
	}
	return nil
}

func readFlags() error {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`TLSX is a tls data gathering toolkit`)

	createGroup(flagSet, "input", "Input",
		flagSet.StringSliceVarP(&options.Inputs, "inputs", "u", []string{}, "target url / list to grab", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringVarP(&options.InputList, "list", "l", "", "target list to perform grabbing of"),
		flagSet.StringSliceVarP(&options.Ports, "port", "p", nil, "port to grab tls data from", goflags.FileCommaSeparatedStringSliceOptions),
	)

	createGroup(flagSet, "configs", "Configurations",
		flagSet.StringVar(&cfgFile, "config", "", "path to the tlsx configuration file"),
		flagSet.IntVar(&options.Timeout, "timeout", 10, "time to wait for request in seconds"),
		flagSet.IntVarP(&options.Concurrency, "concurrency", "c", 300, "number of concurrent threads to process"),
		flagSet.StringVar(&options.MinVersion, "min-version", "", "minimum tls version to accept"),
		flagSet.StringVar(&options.MaxVersion, "max-version", "", "maximum tls version to accept"),
		flagSet.BoolVar(&options.Zcrypto, "ztls", false, "use zmap/zcrypto instead of crypto/tls"),
	)

	createGroup(flagSet, "output", "Output",
		flagSet.StringVarP(&options.OutputFile, "output", "o", "", "file to write output to"),
		flagSet.BoolVar(&options.JSON, "json", false, "display json format output"),
		flagSet.BoolVarP(&options.Verbose, "verbose", "v", false, "display verbose output"),
		flagSet.BoolVar(&options.Version, "version", false, "display project version"),
	)

	if err := flagSet.Parse(); err != nil {
		return errors.Wrap(err, "could not parse flags")
	}

	if cfgFile != "" {
		if err := flagSet.MergeConfigFile(cfgFile); err != nil {
			return errors.Wrap(err, "could not read config file")
		}
	}
	return nil
}

func createGroup(flagSet *goflags.FlagSet, groupName, description string, flags ...*goflags.FlagData) {
	flagSet.SetGroup(groupName, description)
	for _, currentFlag := range flags {
		currentFlag.Group(groupName)
	}
}
