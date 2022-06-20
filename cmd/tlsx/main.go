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
	flagSet.SetDescription(`TLSX is a tls data gathering and analysis toolkit.`)

	flagSet.CreateGroup("input", "Input",
		flagSet.StringSliceVarP(&options.Inputs, "host", "u", []string{}, "target host to scan (-u INPUT1,INPUT2)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringVarP(&options.InputList, "list", "l", "", "target list to scan (-l INPUT_FILE)"),
		flagSet.StringSliceVarP(&options.Ports, "port", "p", nil, "target port to connect (default 443)", goflags.FileCommaSeparatedStringSliceOptions),
	)

	flagSet.CreateGroup("configs", "Configurations",
		flagSet.StringVar(&cfgFile, "config", "", "path to the tlsx configuration file"),
		flagSet.IntVar(&options.Timeout, "timeout", 5, "tls connection timeout in seconds"),
		flagSet.StringVar(&options.ServerName, "sni", "", "tls sni hostname to use"),
		flagSet.IntVarP(&options.Concurrency, "concurrency", "c", 300, "number of concurrent threads to process"),
		flagSet.StringVar(&options.MinVersion, "min-version", "", "minimum tls version to accept (ssl30,tls10,tls11,tls12,tls13)"),
		flagSet.StringVar(&options.MaxVersion, "max-version", "", "maximum tls version to accept (ssl30,tls10,tls11,tls12,tls13)"),
		flagSet.BoolVarP(&options.CertsOnly, "pre-handshake", "ps", false, "enable pre-handshake tls connection (early termination) using ztls"),
		flagSet.StringVarP(&options.ScanMode, "scan-mode", "sm", "", "tls connection mode to use (ctls, ztls, auto)"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.OutputFile, "output", "o", "", "file to write output to"),
		flagSet.BoolVarP(&options.JSON, "json", "j", false, "display json format output"),
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
