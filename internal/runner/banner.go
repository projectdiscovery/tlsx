package runner

import (
	"fmt"
	"os"

	"github.com/pkg/errors"
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
	r.hasStdin = hasStdin()

	if !r.hasStdin && len(r.options.Inputs) == 0 && r.options.InputList == "" {
		return errors.New("no input provided for enumeration")
	}
	if r.options.Port == 0 {
		return errors.New("port is required for input")
	}
	if r.options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	return nil
}

// hasStdin returns true if we have stdin input
func hasStdin() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	if fi.Mode()&os.ModeNamedPipe == 0 {
		return false
	}
	return true
}

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")

	gologger.Print().Label("WRN").Msgf("Use with caution. You are responsible for your actions.\n")
	gologger.Print().Label("WRN").Msgf("Developers assume no liability and are not responsible for any misuse or damage.\n")
}
