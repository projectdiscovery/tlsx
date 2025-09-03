# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## About TLSX

TLSX is a Go-based TLS data gathering and analysis toolkit focused on TLS connection testing, certificate analysis, and security assessment. It's part of the ProjectDiscovery ecosystem and supports multiple TLS connection modes, fingerprinting, and misconfiguration detection.

## Build and Development Commands

- **Build**: `make build` or `go build -v -ldflags '-s -w' -o "tlsx" cmd/tlsx/main.go`
- **Test**: `make test` or `go test -v ./...`
- **Tidy dependencies**: `make tidy` or `go mod tidy`
- **Run single test**: `go test -v ./path/to/specific/package -run TestName`
- **Main executable**: Built as `./tlsx` binary

## Architecture Overview

### Core Structure

- **Entry point**: `cmd/tlsx/main.go` - CLI application entry with flag parsing
- **Runner package**: `internal/runner/` - Orchestrates the execution flow, handles input processing and output coordination
- **Core TLS package**: `pkg/tlsx/` - Contains the main TLS analysis logic and connection handling

### TLS Connection Modes

The toolkit supports multiple TLS connection backends:

- **auto mode** (default): Automatic fallback between connection modes for maximum compatibility
- **ctls**: Uses Go's standard `crypto/tls` library
- **ztls**: Uses ZMap's zcrypto TLS implementation for older TLS versions and advanced analysis
- **openssl**: Uses external OpenSSL binary for specialized operations

Implementation in `pkg/tlsx/`:
- `auto/` - Auto-detection and fallback logic
- `tls/` - Standard Go crypto/tls implementation
- `ztls/` - ZMap zcrypto implementation with JA3 fingerprinting
- `openssl/` - OpenSSL binary integration

### Key Components

- **Client abstraction**: `pkg/tlsx/clients/` - Unified interface for different TLS connection modes
- **Certificate Transparency**: `pkg/ctlogs/` - Streaming CT logs support for real-time certificate monitoring
- **Output handling**: `pkg/output/` - JSON/text output formatting and file writing
- **Fingerprinting**: 
  - `pkg/tlsx/jarm/` - JARM TLS fingerprinting
  - `pkg/tlsx/ztls/ja3/` - JA3 client fingerprinting

### Testing Strategy

- Test files follow Go convention: `*_test.go`
- Unit tests in each package test specific functionality
- Integration tests in `internal/runner/runner_test.go`
- OpenSSL functionality tested in `pkg/tlsx/openssl/openssl_test.go`

## Key Features

- **Multi-mode TLS scanning**: Supports different TLS libraries for comprehensive compatibility
- **Certificate analysis**: Extract SANs, CNs, detect misconfigurations (expired, self-signed, mismatched, revoked, untrusted)
- **TLS fingerprinting**: JARM and JA3 fingerprint generation
- **CT logs streaming**: Real-time certificate transparency log monitoring
- **Flexible input**: Supports ASN, CIDR, IP, hostname, and URL inputs
- **Multiple output formats**: Standard text and JSON output

## Development Notes

- **Go version**: Requires Go 1.24+
- **Dependencies**: Heavy use of ProjectDiscovery libraries (dnsx, fastdialer, goflags, gologger)
- **External tools**: Optional OpenSSL binary for specialized TLS operations
- **Concurrency**: Built-in support for concurrent TLS connections with configurable limits
- **Error handling**: Uses ProjectDiscovery's utils/errors for consistent error handling patterns

## Package Structure

- `assets/` - Embedded data (cipher status, root certificates)
- `cmd/` - Command-line applications and utilities
- `examples/` - Usage examples including CT logs streaming
- `internal/runner/` - Core execution logic, not for external use
- `pkg/` - Public API packages for library usage