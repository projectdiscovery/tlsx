package runner

import (
	"fmt"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/utils/errkit"
	fileutil "github.com/projectdiscovery/utils/file"
	updateutils "github.com/projectdiscovery/utils/update"
)

var banner = fmt.Sprintf(`  

  _____ _    _____  __
 |_   _| |  / __\ \/ /
   | | | |__\__ \>  < 
   |_| |____|___/_/\_\	%s
`, version)

const version = "v1.2.1"

// validateOptions validates the provided options for crawler
func (r *Runner) validateOptions() error {
	// Only call fileutil.HasStdin() if hasStdin hasn't been manually set
	// This allows tests to properly simulate stdin behavior
	if !r.hasStdinSet {
		r.hasStdin = fileutil.HasStdin()
	}

	if r.options.Retries == 0 {
		r.options.Retries = 1
	}
	probeSpecified := r.options.SO || r.options.TLSVersion || r.options.Cipher || r.options.Expired || r.options.SelfSigned || r.options.Hash != "" || r.options.Jarm || r.options.MisMatched || r.options.Revoked || r.options.WildcardCertCheck
	if r.options.RespOnly && probeSpecified {
		return errkit.New("resp-only flag can only be used with san and cn flags")
	}
	if (r.options.SAN || r.options.CN) && probeSpecified {
		return errkit.New("san or cn flag cannot be used with other probes")
	}

	// Enable CT logs mode by default if no input is provided
	if !r.options.CTLogs && !r.hasStdin && len(r.options.Inputs) == 0 && r.options.InputList == "" {
		r.options.CTLogs = true
		r.options.SAN = true // Enable SAN by default in CT logs mode
	}

	// Check if we still have no input after auto-enabling CT logs
	if !r.options.CTLogs && !r.hasStdin && len(r.options.Inputs) == 0 && r.options.InputList == "" {
		return errkit.New("no input provided for enumeration")
	}

	if len(r.options.Ports) == 0 {
		// Append port 443 for default ports
		r.options.Ports = append(r.options.Ports, "443")
	}
	if r.options.CertsOnly && (r.options.ScanMode != "ztls" && r.options.ScanMode != "auto") {
		return errkit.New("scan-mode must be ztls or auto with certs-only option")
	}
	if r.options.CertsOnly || r.options.Ja3 || r.options.Ja3s {
		r.options.ScanMode = "ztls" // force setting ztls when using certs-only
	}
	if r.options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}

	if r.options.Jarm && r.options.Delay != "" {
		gologger.Info().Label("WRN").Msg("Using connection pooling for jarm hash calculation, delay will not work as expected")
	}
	return nil
}

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")
}

// GetUpdateCallback returns a callback function that updates tlsx
func GetUpdateCallback() func() {
	return func() {
		showBanner()
		updateutils.GetUpdateToolCallback("tlsx", version)()
	}
}
