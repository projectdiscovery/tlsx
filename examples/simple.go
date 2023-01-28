package main

import (
	"fmt"

	"github.com/projectdiscovery/tlsx/pkg/tlsx"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
)

func main() {
	// setup tlsx client with options
	// https://pkg.go.dev/github.com/projectdiscovery/tlsx/pkg/tlsx/clients#Options
	opts := &clients.Options{
		TLSVersion: true,
		Retries:    3,
		Expired:    true,
	}

	// available scanmodes
	allmodes := []string{"auto", "openssl", "ctls", "ztls"}

	for _, scanMode := range allmodes {
		opts.ScanMode = scanMode
		// create tlsx service with options
		service, err := tlsx.New(opts)
		if err != nil {
			panic(err)
		}

		// connect to any host either with hostname or ip
		// service.Connect(hostname, ip , port string)
		resp, err := service.Connect("scanme.sh", "", "443")
		if err != nil {
			panic(err)
		}

		fmt.Printf("[%v] scan-mode:%-7v tls-version:%v self-signed:%v cipher:%v\n", resp.Host, scanMode, resp.Version, resp.SelfSigned, resp.Cipher)
	}
}
