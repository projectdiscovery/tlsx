package runner

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

var banner = fmt.Sprintf(`  

  _____ _    _____  __
 |_   _| |  / __\ \/ /
   | | | |__\__ \>  < 
   |_| |____|___/_/\_\	%s
`, version)

var version = "v0.0.1"

// validateOptions validates the provided options for crawler
func (r *Runner) validateOptions() error {
	r.hasStdin = fileutil.HasStdin()

	if !r.hasStdin && len(r.options.Inputs) == 0 && r.options.InputList == "" {
		return errors.New("no input provided for enumeration")
	}
	if len(r.options.Ports) == 0 {
		// Append port 443 for default ports
		r.options.Ports = append(r.options.Ports, "443")
	}
	if r.options.CertsOnly && !r.options.Zcrypto {
		return errors.New("certs-only flag can only be used with ztls flag")
	}
	if r.options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	return nil
}

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")

	gologger.Print().Label("WRN").Msgf("Use with caution. You are responsible for your actions.\n")
	gologger.Print().Label("WRN").Msgf("Developers assume no liability and are not responsible for any misuse or damage.\n")
}
