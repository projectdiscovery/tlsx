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

	flagSet.CreateGroup("scan-mode", "Scan-Mode",
		flagSet.StringVarP(&options.ScanMode, "scan-mode", "sm", "", "tls connection mode to use (ctls, ztls, auto) (default ctls)"),
		flagSet.BoolVarP(&options.CertsOnly, "pre-handshake", "ps", false, "enable pre-handshake tls connection (early termination) using ztls"),
	)

	flagSet.CreateGroup("probes", "Probes",
		flagSet.BoolVar(&options.SAN, "san", false, "display subject alternative names"),
		flagSet.BoolVar(&options.CN, "cn", false, "display subject common names"),
		flagSet.BoolVar(&options.SO, "so", false, "display subject organization name"),
		flagSet.BoolVarP(&options.TLSVersion, "tls-version", "tv", false, "display used tls version"),
		flagSet.BoolVar(&options.Cipher, "cipher", false, "display used cipher"),
		flagSet.StringVar(&options.Hash, "hash", "", "display certificate fingerprint hashes (md5,sha1,sha256)"),
		flagSet.BoolVar(&options.Jarm, "jarm", false, "display jarm fingerprint hash"),
		flagSet.BoolVarP(&options.ProbeStatus, "probe-status", "tps", false, "display tls probe status"),
	)

	flagSet.CreateGroup("misconfigurations", "Misconfigurations",
		flagSet.BoolVarP(&options.Expired, "expired", "ex", false, "display validity status of certificate"),
		flagSet.BoolVarP(&options.SelfSigned, "self-signed", "ss", false, "display status of self-signed certificate"),
	)

	flagSet.CreateGroup("configs", "Configurations",
		flagSet.StringVar(&cfgFile, "config", "", "path to the tlsx configuration file"),
		flagSet.StringSliceVarP(&options.Resolvers, "resolvers", "r", nil, "list of resolvers to use", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.StringVarP(&options.CACertificate, "cacert", "cc", "", "client certificate authority file"),
		flagSet.StringSliceVarP(&options.Ciphers, "cipher-input", "ci", nil, "ciphers to use with tls connection", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.StringVar(&options.ServerName, "sni", "", "tls sni hostname to use"),
		flagSet.StringVar(&options.MinVersion, "min-version", "", "minimum tls version to accept (ssl30,tls10,tls11,tls12,tls13)"),
		flagSet.StringVar(&options.MaxVersion, "max-version", "", "maximum tls version to accept (ssl30,tls10,tls11,tls12,tls13)"),
		flagSet.BoolVarP(&options.TLSChain, "tls-chain", "tc", false, "display tls chain in json output"),
		flagSet.BoolVarP(&options.VerifyServerCertificate, "verify-cert", "vc", false, "enable verification of server certificate"),
	)

	flagSet.CreateGroup("optimizations", "Optimizations",
		flagSet.IntVarP(&options.Concurrency, "concurrency", "c", 300, "number of concurrent threads to process"),
		flagSet.IntVar(&options.Timeout, "timeout", 5, "tls connection timeout in seconds"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.OutputFile, "output", "o", "", "file to write output to"),
		flagSet.BoolVarP(&options.JSON, "json", "j", false, "display json format output"),
		flagSet.BoolVarP(&options.RespOnly, "resp-only", "ro", false, "display tls response only"),
		flagSet.BoolVar(&options.Silent, "silent", false, "display silent output"),
		flagSet.BoolVarP(&options.NoColor, "no-color", "nc", false, "disable colors in cli output"),
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
