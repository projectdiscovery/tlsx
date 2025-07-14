package main

import (
	"crypto/x509"
	"fmt"

	"github.com/projectdiscovery/tlsx/pkg/ctlogs"
)

// Quick-start example: stream Certificate-Transparency (CT) logs, print the
// very first certificate we receive and then exit.
//
//	go run .
//
// How it works:
//  1. We create a ctlogs.Service with a callback.
//  2. The callback prints the certificate and signals "done" the first time
//     it is invoked (duplicates are ignored).
//  3. main() waits on the signal, stops the service and exits.
//
// Only a few lines – perfect for first-time users.
func main() {
	// The callback will send a value on this channel once – that’s our cue to
	// stop. A buffer of 1 ensures the send never blocks.
	done := make(chan struct{}, 1)

	callback := func(meta ctlogs.EntryMeta, raw []byte, duplicate bool) {
		if duplicate {
			return
		}
		// Try to signal completion. If the channel is already full, we've
		// processed a certificate before, so simply return.
		select {
		case done <- struct{}{}:
			// This is the first certificate – print a summary.
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				return
			}
			fmt.Printf("CT log %s (index %d) CN=%s\n", meta.SourceDesc, meta.Index, cert.Subject.CommonName)
		default:
			// Channel already has a value – we’ve printed our first cert.
		}
	}

	svc, err := ctlogs.New(
		ctlogs.WithStartNow(),     // fetch logs starting from now
		ctlogs.WithVerbose(false), // silence internal logs
		ctlogs.WithCallback(callback),
	)
	if err != nil {
		panic(err)
	}

	svc.Start()
	<-done     // wait for the callback to signal completion
	svc.Stop() // graceful shutdown
}
