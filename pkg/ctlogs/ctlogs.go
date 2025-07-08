package ctlogs

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	boom "github.com/tylertreat/BoomFilters"
)

// CTLogInfo represents a CT log from the official log list
type CTLogInfo struct {
	Description string `json:"description"`
	LogID       string `json:"log_id"`
	Key         string `json:"key"`
	URL         string `json:"url"`
	MMD         int    `json:"mmd"` // Maximum Merge Delay
}

// CTOperator represents a CT log operator
type CTOperator struct {
	Name  string      `json:"name"`
	Email []string    `json:"email"`
	Logs  []CTLogInfo `json:"logs"`
}

// CTLogList represents the official Google CT log list
type CTLogList struct {
	Version   string       `json:"version"`
	Operators []CTOperator `json:"operators"`
}

// CTLogSource represents a Certificate Transparency log source
type CTLogSource struct {
	Client     *CTLogClient
	LastSize   uint64
	WindowSize uint64 // Sliding window size
}

// CTLogsService handles Certificate Transparency logs streaming
type CTLogsService struct {
	options    ServiceOptions
	sources    []*CTLogSource

	// Deprecated: retained for backward compatibility until CLI refactor is done.
	outputChan chan *clients.Response

	deduper *boom.InverseBloomFilter

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// CTLogEntry represents a single CT log entry
type CTLogEntry struct {
	LeafInput string `json:"leaf_input"`
	ExtraData string `json:"extra_data"`
}

// CTLogResponse represents the response from a CT log API
type CTLogResponse struct {
	Entries []CTLogEntry `json:"entries"`
}

// New constructs a CTLogsService using the supplied functional options.
//
// For the time being we also allow passing *clients.Options for legacy callers;
// this parameter will be removed in a subsequent milestone.
func New(legacyOpts *clients.Options, optFns ...ServiceOption) (*CTLogsService, error) {
	// Build ServiceOptions with defaults, apply functional overrides, then
	// copy values from legacy opts for compatibility.
	opts := defaultServiceOptions()
	for _, fn := range optFns {
		fn(&opts)
	}
	if legacyOpts != nil {
		opts.Verbose = opts.Verbose || legacyOpts.Verbose
		opts.Cert = opts.Cert || legacyOpts.Cert
	}

	ctx, cancel := context.WithCancel(context.Background())

	svc := &CTLogsService{
		options:    opts,
		outputChan: make(chan *clients.Response, 1000), // deprecate later
		ctx:        ctx,
		cancel:     cancel,
	}

	// Initialize inverse bloom filter for deduplication.
	svc.deduper = boom.NewInverseBloomFilter(uint(opts.DedupeSize))

	if err := svc.initializeSources(); err != nil {
		return nil, err
	}
	return svc, nil
}

// initializeSources fetches and initializes CT log sources from the official Google log list
func (service *CTLogsService) initializeSources() error {
	gologger.Info().Msg("Fetching CT log list from Google...")

	resp, err := http.Get("https://www.gstatic.com/ct/log_list/v3/log_list.json")
	if err != nil {
		return fmt.Errorf("failed to fetch CT log list: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			gologger.Warning().Msgf("Failed to close response body: %v", err)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read CT log list: %w", err)
	}

	var logList CTLogList
	if err := json.Unmarshal(body, &logList); err != nil {
		return fmt.Errorf("failed to parse CT log list: %w", err)
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	logCount := 0

	// Create a context with timeout for initialization
	initCtx, cancel := context.WithTimeout(service.ctx, 30*time.Second)
	defer cancel()

	for _, operator := range logList.Operators {
		for _, logInfo := range operator.Logs {
			if logInfo.MMD > 86400 {
				continue
			}
			wg.Add(1)
			go func(logInfo CTLogInfo) {
				defer wg.Done()
				client, err := NewCTLogClient(logInfo, WithHTTPClient(&http.Client{
					Timeout: 10 * time.Second,
				}))
				if err != nil {
					if service.options.Verbose {
						gologger.Warning().Msgf("Failed to create client for %s: %v", logInfo.Description, err)
					}
					return
				}
				sth, err := client.GetSTH(initCtx)
				if err != nil {
					if service.options.Verbose {
						gologger.Warning().Msgf("Failed to get STH for %s: %v", logInfo.Description, err)
					}
					return
				}
				// Start tailing from last 1000 entries
				var startSize uint64 = 0
				if sth.TreeSize > 1000 {
					startSize = sth.TreeSize - 1000
				}
				source := &CTLogSource{
					Client:     client,
					LastSize:   startSize,
					WindowSize: 1000, // Process last 1000 entries
				}
				mu.Lock()
				service.sources = append(service.sources, source)
				logCount++
				mu.Unlock()
			}(logInfo)
		}
	}

	// Wait with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All goroutines completed
	case <-initCtx.Done():
		// Timeout reached, continue with whatever we have
		gologger.Warning().Msg("Initialization timeout reached, continuing with available logs")
	}

	gologger.Info().Msgf("Initialized %d CT log sources", logCount)
	return nil
}

// Start begins streaming from all CT log sources
func (service *CTLogsService) Start() {
	gologger.Info().Msg("Starting CT logs streaming…")

	for _, source := range service.sources {
		service.wg.Add(1)
		go service.streamFromSource(source)
	}
}

// Stop stops the streaming service
func (service *CTLogsService) Stop() {
	service.cancel()
	service.wg.Wait()
	close(service.outputChan)
}

// GetOutputChannel exposes the deprecated channel-based interface.
// Will be removed in a future milestone once all call-sites migrate.
func (service *CTLogsService) GetOutputChannel() <-chan *clients.Response {
	return service.outputChan
}

// streamFromSource continuously streams from a single CT log source
func (service *CTLogsService) streamFromSource(source *CTLogSource) {
	defer service.wg.Done()

	// Process initial batch immediately
	if err := service.fetchNewEntries(source); err != nil {
		if service.options.Verbose {
			gologger.Error().Msgf("Error in initial fetch from %s: %v", source.Client.Info().Description, err)
		}
	}

	// Use a reasonable polling interval instead of MMD-based rate limiting
	pollInterval := service.options.PollInterval
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-service.ctx.Done():
			return
		case <-ticker.C:
			if err := service.fetchNewEntries(source); err != nil {
				if service.options.Verbose {
					gologger.Error().Msgf("Error fetching from %s: %v", source.Client.Info().Description, err)
				}
				// Continue trying even if there's an error
			}
		}
	}
}

// fetchNewEntries fetches new entries from a CT log source using sliding window
func (service *CTLogsService) fetchNewEntries(source *CTLogSource) error {
	// Get current tree size
	sth, err := source.Client.GetSTH(service.ctx)
	if err != nil {
		return fmt.Errorf("failed to get STH: %w", err)
	}

	// Calculate range to fetch (sliding window)
	start := source.LastSize
	end := start + source.WindowSize
	if end > sth.TreeSize {
		end = sth.TreeSize
	}

	if start >= end {
		return nil
	}

	// Fetch entries
	entries, err := source.Client.GetEntries(service.ctx, start, end-1)
	if err != nil {
		return fmt.Errorf("failed to get entries: %w", err)
	}

	if service.options.Verbose {
		gologger.Info().Msgf("[%s] Fetched %d entries (%d-%d)", source.Client.Info().Description, len(entries), start, end-1)
	}

	// Process all certificates - no filtering
	for i, entry := range entries {
		if err := service.processEntry(source, &entry, start+uint64(i)); err != nil {
			if service.options.Verbose {
				gologger.Error().Msgf("Error processing entry from %s: %v", source.Client.Info().Description, err)
			}
			continue
		}
	}

	// Update last size
	source.LastSize = end

	return nil
}

// processEntry processes a single CT log entry
func (service *CTLogsService) processEntry(source *CTLogSource, entry *ct.LogEntry, index uint64) error {
	// Skip if no X509 certificate
	if entry.X509Cert == nil {
		return nil
	}

	// Convert CT certificate to standard x509 certificate
	cert, err := x509.ParseCertificate(entry.X509Cert.Raw)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Build uniqueness key and check deduper
	uniqKey := cert.Issuer.String() + cert.SerialNumber.String()
	duplicate := service.deduper.TestAndAdd([]byte(uniqKey))

	// Process all certificates - no filtering
	if duplicate && service.options.Callback == nil {
		// Skip duplicates when using legacy channel approach.
		return nil
	}

	response := service.certificateToResponse(cert, source.Client.Info().Description)
	if response == nil {
		return nil
	}

	// Invoke callback if configured.
	if service.options.Callback != nil {
		meta := EntryMeta{
			SourceID:       service.formatSourceID(source.Client.Info().Description),
			SourceDesc:     source.Client.Info().Description,
			Index:          index,
			CollectionTime: time.Now(),
		}

		service.options.Callback(meta, cert.Raw, duplicate)
	} else {
		// Fallback to channel for legacy behaviour.
		select {
		case service.outputChan <- response:
			// Only verbose local log
			if service.options.Verbose {
				gologger.Info().Msgf("[%s] %s", source.Client.Info().Description, response.Host)
			}
		default:
			if service.options.Verbose {
				gologger.Warning().Msgf("Output channel full, skipping entry from %s", source.Client.Info().Description)
			}
		}
	}

	return nil
}

// certificateToResponse converts an x509 certificate to tlsx response format
func (service *CTLogsService) certificateToResponse(cert *x509.Certificate, sourceName string) *clients.Response {
	now := time.Now()

	// Determine host from certificate
	host := ""
	if len(cert.DNSNames) > 0 {
		host = cert.DNSNames[0]
	} else if cert.Subject.CommonName != "" {
		host = cert.Subject.CommonName
	}

	// Skip certificates without a hostname
	if host == "" {
		return nil
	}

	// Create certificate response
	certResp := &clients.CertificateResponse{
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		SubjectDN:    cert.Subject.String(),
		SubjectCN:    cert.Subject.CommonName,
		SubjectAN:    cert.DNSNames,
		Serial:       cert.SerialNumber.String(),
		IssuerDN:     cert.Issuer.String(),
		IssuerCN:     cert.Issuer.CommonName,
		Expired:      cert.NotAfter.Before(now),
		SelfSigned:   clients.IsSelfSigned(cert.AuthorityKeyId, cert.SubjectKeyId),
		WildCardCert: clients.IsWildCardCert(cert.DNSNames),
	}

	// Add organization information
	if len(cert.Subject.Organization) > 0 {
		certResp.SubjectOrg = cert.Subject.Organization
	}
	if len(cert.Issuer.Organization) > 0 {
		certResp.IssuerOrg = cert.Issuer.Organization
	}

	// Add fingerprint hashes
	certResp.FingerprintHash = clients.CertificateResponseFingerprintHash{
		MD5:    clients.MD5Fingerprint(cert.Raw),
		SHA1:   clients.SHA1Fingerprint(cert.Raw),
		SHA256: clients.SHA256Fingerprint(cert.Raw),
	}

	// Add certificate in PEM format if requested
	if service.options.Cert {
		certResp.Certificate = clients.PemEncode(cert.Raw)
	}

	// Create response
	response := &clients.Response{
		Timestamp:           &now,
		Host:                host,
		Port:                "443", // Default HTTPS port
		ProbeStatus:         true,
		CertificateResponse: certResp,
		CTLogSource:         service.formatSourceID(sourceName),
	}

	return response
}

// formatSourceID converts a CT log source name to an ID format
func (service *CTLogsService) formatSourceID(sourceName string) string {
	// Remove quotes and convert to lowercase with underscores
	// Example: "Google 'Xenon2025h2'" -> "google_xenon2025h2"
	id := strings.ToLower(sourceName)
	id = strings.ReplaceAll(id, "'", "")
	id = strings.ReplaceAll(id, " ", "_")
	id = strings.ReplaceAll(id, "-", "_")
	return id
}
