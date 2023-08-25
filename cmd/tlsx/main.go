package main

import (
	"os"
	"strings"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/tlsx/internal/runner"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/openssl"
	errorutils "github.com/projectdiscovery/utils/errors"
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
		return errorutils.NewWithErr(err).Msgf("could not read flags")
	}
	runner, err := runner.New(options)
	if err != nil {
		return errorutils.NewWithErr(err).Msgf("could not create runner")
	}
	if runner == nil {
		return nil
	}
	if err := runner.Execute(); err != nil {
		return errorutils.NewWithErr(err).Msgf("could not execute runner")
	}
	if err := runner.Close(); err != nil {
		return errorutils.NewWithErr(err).Msgf("could not close runner")
	}
	return nil
}

func readFlags() error {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`TLSX is a tls data gathering and analysis toolkit.`)

	flagSet.CreateGroup("input", "Input",
		flagSet.StringSliceVarP(&options.Inputs, "host", "u", nil, "target host to scan (-u INPUT1,INPUT2)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringVarP(&options.InputList, "list", "l", "", "target list to scan (-l INPUT_FILE)"),
		flagSet.StringSliceVarP(&options.Ports, "port", "p", nil, "target port to connect (default 443)", goflags.FileCommaSeparatedStringSliceOptions),
	)

	availableScanModes := []string{"ctls", "ztls"}
	if openssl.IsAvailable() {
		availableScanModes = append(availableScanModes, "openssl")
	}
	availableScanModes = append(availableScanModes, "auto")

	flagSet.CreateGroup("scan-mode", "Scan-Mode",
		flagSet.StringVarP(&options.ScanMode, "scan-mode", "sm", "auto", "tls connection mode to use ("+strings.Join(availableScanModes, ", ")+")"),
		flagSet.BoolVarP(&options.CertsOnly, "pre-handshake", "ps", false, "enable pre-handshake tls connection (early termination) using ztls"),
		flagSet.BoolVarP(&options.ScanAllIPs, "scan-all-ips", "sa", false, "scan all ips for a host (default false)"),
		flagSet.StringSliceVarP(&options.IPVersion, "ip-version", "iv", nil, "ip version to use (4, 6) (default 4)", goflags.NormalizedStringSliceOptions),
	)

	flagSet.CreateGroup("probes", "Probes",
		flagSet.BoolVar(&options.SAN, "san", false, "display subject alternative names"),
		flagSet.BoolVar(&options.CN, "cn", false, "display subject common names"),
		flagSet.BoolVar(&options.SO, "so", false, "display subject organization name"),
		flagSet.BoolVarP(&options.TLSVersion, "tls-version", "tv", false, "display used tls version"),
		flagSet.BoolVar(&options.Cipher, "cipher", false, "display used cipher"),
		flagSet.StringVar(&options.Hash, "hash", "", "display certificate fingerprint hashes (md5,sha1,sha256)"),
		flagSet.BoolVar(&options.Jarm, "jarm", false, "display jarm fingerprint hash"),
		flagSet.BoolVar(&options.Ja3, "ja3", false, "display ja3 fingerprint hash (using ztls)"),
		flagSet.BoolVarP(&options.WildcardCertCheck, "wildcard-cert", "wc", false, "display host with wildcard ssl certificate"),
		flagSet.BoolVarP(&options.ProbeStatus, "probe-status", "tps", false, "display tls probe status"),
		flagSet.BoolVarP(&options.TlsVersionsEnum, "version-enum", "ve", false, "enumerate and display supported tls versions"),
		flagSet.BoolVarP(&options.TlsCiphersEnum, "cipher-enum", "ce", false, "enumerate and display supported cipher"),
		flagSet.EnumSliceVarP(&options.TLsCipherLevel, "cipher-type", "ct", []goflags.EnumVariable{goflags.EnumVariable(0)}, "ciphers types to enumerate. possible values: all/secure/insecure/weak (comma-separated)", goflags.AllowdTypes{
			"all":      goflags.EnumVariable(clients.All),
			"weak":     goflags.EnumVariable(clients.Weak),
			"insecure": goflags.EnumVariable(clients.Insecure),
			"secure":   goflags.EnumVariable(clients.Secure),
		}),
		flagSet.BoolVarP(&options.ClientHello, "client-hello", "ch", false, "include client hello in json output (ztls mode only)"),
		flagSet.BoolVarP(&options.ServerHello, "server-hello", "sh", false, "include server hello in json output (ztls mode only)"),
		flagSet.BoolVarP(&options.Serial, "serial", "se", false, "display certificate serial number"),
	)

	flagSet.CreateGroup("misconfigurations", "Misconfigurations",
		flagSet.BoolVarP(&options.Expired, "expired", "ex", false, "display host with host expired certificate"),
		flagSet.BoolVarP(&options.SelfSigned, "self-signed", "ss", false, "display host with self-signed certificate"),
		flagSet.BoolVarP(&options.MisMatched, "mismatched", "mm", false, "display host with mismatched certificate"),
		flagSet.BoolVarP(&options.Revoked, "revoked", "re", false, "display host with revoked certificate"),
		flagSet.BoolVarP(&options.Untrusted, "untrusted", "un", false, "display host with untrusted certificate"),
	)

	flagSet.CreateGroup("configs", "Configurations",
		flagSet.StringVar(&cfgFile, "config", "", "path to the tlsx configuration file"),
		flagSet.StringSliceVarP(&options.Resolvers, "resolvers", "r", nil, "list of resolvers to use", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.StringVarP(&options.CACertificate, "cacert", "cc", "", "client certificate authority file"),
		flagSet.StringSliceVarP(&options.Ciphers, "cipher-input", "ci", nil, "ciphers to use with tls connection", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.StringSliceVar(&options.ServerName, "sni", nil, "tls sni hostname to use", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.BoolVarP(&options.RandomForEmptyServerName, "random-sni", "rs", false, "use random sni when empty"),
		flagSet.BoolVarP(&options.ReversePtrSNI, "rev-ptr-sni", "rps", false, "perform reverse PTR to retrieve SNI from IP"),
		flagSet.StringVar(&options.MinVersion, "min-version", "", "minimum tls version to accept (ssl30,tls10,tls11,tls12,tls13)"),
		flagSet.StringVar(&options.MaxVersion, "max-version", "", "maximum tls version to accept (ssl30,tls10,tls11,tls12,tls13)"),
		flagSet.BoolVarP(&options.Cert, "certificate", "cert", false, "include certificates in json output (PEM format)"),
		flagSet.BoolVarP(&options.TLSChain, "tls-chain", "tc", false, "include certificates chain in json output"),
		flagSet.BoolVarP(&options.VerifyServerCertificate, "verify-cert", "vc", false, "enable verification of server certificate"),
		flagSet.StringVarP(&options.OpenSSLBinary, "openssl-binary", "ob", "", "OpenSSL Binary Path"),
		flagSet.BoolVarP(&options.HardFail, "hardfail", "hf", false, "strategy to use if encountered errors while checking revocation status"),
	)

	flagSet.CreateGroup("optimizations", "Optimizations",
		flagSet.IntVarP(&options.Concurrency, "concurrency", "c", 300, "number of concurrent threads to process"),
		flagSet.IntVarP(&options.CipherConcurrency, "cipher-concurrency", "cec", 10, "cipher enum concurrency for each target"),
		flagSet.IntVar(&options.Timeout, "timeout", 5, "tls connection timeout in seconds"),
		flagSet.IntVar(&options.Retries, "retry", 3, "number of retries to perform for failures"),
		flagSet.StringVar(&options.Delay, "delay", "", "duration to wait between each connection per thread (eg: 200ms, 1s)"),
	)

	flagSet.CreateGroup("update", "Update",
		flagSet.CallbackVarP(runner.GetUpdateCallback(), "update", "up", "update tlsx to latest version"),
		flagSet.BoolVarP(&options.DisableUpdateCheck, "disable-update-check", "duc", false, "disable automatic tlsx update check"),
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

	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVarP(&options.HealthCheck, "hc", "health-check", false, "run diagnostic check up"),
	)

	if err := flagSet.Parse(); err != nil {
		return errorutils.NewWithErr(err).Msgf("could not parse flags")
	}

	if options.HealthCheck {
		gologger.Print().Msgf("%s\n", runner.DoHealthCheck(flagSet))
		os.Exit(0)
	}

	if cfgFile != "" {
		if err := flagSet.MergeConfigFile(cfgFile); err != nil {
			return errorutils.NewWithErr(err).Msgf("could not read config file")
		}
	}
	return nil
}

func init() {
	// Feature: Debug Mode
	// Errors will include stacktrace when debug mode is enabled
	if os.Getenv("DEBUG") != "" {
		errorutils.ShowStackTrace = true
	}
}
