package runner

import (
	"bufio"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/mapcidr/asn"
	"github.com/projectdiscovery/tlsx/pkg/output"
	"github.com/projectdiscovery/tlsx/pkg/output/stats"
	"github.com/projectdiscovery/tlsx/pkg/tlsx"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/openssl"
	errorutil "github.com/projectdiscovery/utils/errors"
	iputil "github.com/projectdiscovery/utils/ip"
	sliceutil "github.com/projectdiscovery/utils/slice"
	updateutils "github.com/projectdiscovery/utils/update"
)

// Runner is a client for running the enumeration process
type Runner struct {
	hasStdin     bool
	outputWriter output.Writer
	fastDialer   *fastdialer.Dialer
	options      *clients.Options
	dnsclient    *dnsx.DNSX
}

// New creates a new runner from provided configuration options
func New(options *clients.Options) (*Runner, error) {
	// Disable coloring of log output if asked by user
	if options.NoColor {
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
	}
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
	if options.OpenSSLBinary != "" {
		openssl.UseOpenSSLBinary(options.OpenSSLBinary)
	}
	if options.TlsCiphersEnum {
		// cipher enumeration requires tls versions
		options.TlsVersionsEnum = true
	}
	showBanner()

	if options.Version {
		gologger.Info().Msgf("Current version: %s", version)
		return nil, nil
	}

	if !options.DisableUpdateCheck {
		latestVersion, err := updateutils.GetToolVersionCallback("tlsx", version)()
		if err != nil {
			if options.Verbose {
				gologger.Error().Msgf("tlsx version check failed: %v", err.Error())
			}
		} else {
			gologger.Info().Msgf("Current tlsx version %v %v", version, updateutils.GetVersionDescription(version, latestVersion))
		}
	}

	runner := &Runner{options: options}
	if err := runner.validateOptions(); err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("could not validate options")
	}

	dialerOpts := fastdialer.DefaultOptions
	dialerOpts.WithDialerHistory = true
	dialerOpts.MaxRetries = 3
	dialerOpts.DialerTimeout = time.Duration(options.Timeout) * time.Second
	if len(options.Resolvers) > 0 {
		dialerOpts.BaseResolvers = options.Resolvers
	}
	fastDialer, err := fastdialer.NewDialer(dialerOpts)
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("could not create dialer")
	}
	runner.fastDialer = fastDialer
	runner.options.Fastdialer = fastDialer

	dnsOptions := dnsx.DefaultOptions
	dnsOptions.MaxRetries = runner.options.Retries
	dnsOptions.Hostsfile = true
	if sliceutil.Contains(options.IPVersion, "6") {
		dnsOptions.QuestionTypes = append(dnsOptions.QuestionTypes, dns.TypeAAAA)
	}
	dnsclient, err := dnsx.New(dnsOptions)
	if err != nil {
		return nil, err
	}
	runner.dnsclient = dnsclient

	outputWriter, err := output.New(options)
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("could not create output writer")
	}
	runner.outputWriter = outputWriter

	return runner, nil
}

// Close closes the runner releasing resources
func (r *Runner) Close() error {
	_ = r.outputWriter.Close()
	r.fastDialer.Close()
	return nil
}

type taskInput struct {
	host string
	ip   string
	port string
	sni  string
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
	if err := r.normalizeAndQueueInputs(inputs); err != nil {
		gologger.Error().Msgf("Could not normalize queue inputs: %s", err)
	}

	close(inputs)
	wg.Wait()

	// Print the stats if auto fallback mode is used
	if r.options.ScanMode == "auto" {
		gologger.Info().Msgf("Connections made using crypto/tls: %d, zcrypto/tls: %d, openssl: %d", stats.LoadCryptoTLSConnections(), stats.LoadZcryptoTLSConnections(), stats.LoadOpensslTLSConnections())
	}
	return nil
}

// processInputElementWorker processes an element from input
func (r *Runner) processInputElementWorker(inputs chan taskInput, wg *sync.WaitGroup) {
	defer wg.Done()

	tlsxService, err := tlsx.New(r.options)
	if err != nil {
		gologger.Fatal().Msgf("could not create tlsx client: %s", err)
		return
	}

	for task := range inputs {
		if r.options.Delay != "" {
			duration, err := time.ParseDuration(r.options.Delay)
			if err != nil {
				gologger.Error().Msgf("error parsing delay %s: %s", r.options.Delay, err)
			}
			time.Sleep(duration)
		}
		if r.options.Verbose {
			gologger.Info().Msgf("Processing input %s:%s", task.host, task.port)
		}

		response, err := tlsxService.ConnectWithOptions(task.host, task.ip, task.port, clients.ConnectOptions{SNI: task.sni})
		if err != nil {
			gologger.Warning().Msgf("Could not connect input %s: %s", task.Address(), err)
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
			return errorutil.NewWithErr(err).Msgf("could not open input file")
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

// resolveFQDN resolves a FQDN and returns the IP addresses
func (r *Runner) resolveFQDN(target string) ([]string, error) {
	// If the host is a Domain, then perform resolution and discover all IP
	// addresses for a given host. Else use that host
	var hostIPs []string
	if !iputil.IsIP(target) {
		dnsData, err := r.dnsclient.QueryMultiple(target)
		if err != nil || dnsData == nil {
			gologger.Warning().Msgf("Could not get IP for host: %s\n", target)
			return nil, err
		}
		if len(r.options.IPVersion) > 0 {
			if sliceutil.Contains(r.options.IPVersion, "4") {
				hostIPs = append(hostIPs, dnsData.A...)
			}
			if sliceutil.Contains(r.options.IPVersion, "6") {
				hostIPs = append(hostIPs, dnsData.AAAA...)
			}
		} else {
			hostIPs = append(hostIPs, dnsData.A...)
		}
	} else {
		hostIPs = append(hostIPs, target)
	}
	return hostIPs, nil
}

// processInputItem processes a single input item
func (r *Runner) processInputItem(input string, inputs chan taskInput) {
	// AS Input
	if asn.IsASN(input) {
		r.processInputASN(input, inputs)
		return
	}
	// CIDR input
	if _, ipRange, _ := net.ParseCIDR(input); ipRange != nil {
		r.processInputCIDR(input, inputs)
		return
	}
	if r.options.ScanAllIPs || len(r.options.IPVersion) > 0 {
		r.processInputForMultipleIPs(input, inputs)
		return
	}
	// Normal input
	host, customPort := r.getHostPortFromInput(input)
	if customPort == "" {
		for _, port := range r.options.Ports {
			r.processInputItemWithSni(taskInput{host: host, port: port}, inputs)
		}
	} else {
		r.processInputItemWithSni(taskInput{host: host, port: customPort}, inputs)
	}
}

func (r *Runner) processInputItemWithSni(task taskInput, inputs chan taskInput) {
	if len(r.options.ServerName) > 0 {
		for _, serverName := range r.options.ServerName {
			task.sni = serverName
			inputs <- task
		}
	} else {
		inputs <- task
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

// processInputASN processes a single ASN input
func (r *Runner) processInputASN(input string, inputs chan taskInput) {
	ips, err := asn.GetIPAddressesAsStream(input)
	if err != nil {
		gologger.Error().Msgf("Could not get IP addresses for %s: %s", input, err)
		return
	}
	for ip := range ips {
		for _, port := range r.options.Ports {
			r.processInputItemWithSni(taskInput{host: ip, port: port}, inputs)
		}
	}
}

// processInputCIDR processes a single ASN input
func (r *Runner) processInputCIDR(input string, inputs chan taskInput) {
	cidrInputs, err := mapcidr.IPAddressesAsStream(input)
	if err != nil {
		gologger.Error().Msgf("Could not parse cidr %s: %s", input, err)
		return
	}
	for cidr := range cidrInputs {
		for _, port := range r.options.Ports {
			r.processInputItemWithSni(taskInput{host: cidr, port: port}, inputs)
		}
	}
}

// processInputForMultipleIPs processes single input if scanall and IPVersion flag is passed
func (r *Runner) processInputForMultipleIPs(input string, inputs chan taskInput) {
	host, customPort := r.getHostPortFromInput(input)
	// If the host is a Domain, then perform resolution and discover all IP's
	ipList, err := r.resolveFQDN(host)
	if err != nil {
		gologger.Warning().Msgf("Could not resolve %s: %s", host, err)
		return
	}
	for _, ip := range ipList {
		if customPort == "" {
			for _, port := range r.options.Ports {
				r.processInputItemWithSni(taskInput{host: host, ip: ip, port: port}, inputs)
			}
		} else {
			r.processInputItemWithSni(taskInput{host: host, ip: ip, port: customPort}, inputs)
		}
	}
}
