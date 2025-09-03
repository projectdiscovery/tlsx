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
	"sync/atomic"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	boom "github.com/tylertreat/BoomFilters"
)

// CTLogsService handles Certificate Transparency logs streaming
type CTLogsService struct {
	options ServiceOptions
	sources []*CTLogSource

	deduper *boom.InverseBloomFilter

	// atomic counters
	totalCert    atomic.Uint64
	duplicates   atomic.Uint64
	uniqueCert   atomic.Uint64
	backoffRetry atomic.Uint64

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New constructs a CTLogsService using the supplied functional options.
//
// For the time being we also allow passing *clients.Options for legacy callers;
// this parameter will be removed in a subsequent milestone.
func New(optFns ...ServiceOption) (*CTLogsService, error) {
	// Build ServiceOptions with defaults, apply functional overrides, then
	// copy values from legacy opts for compatibility.
	opts := defaultServiceOptions()
	for _, fn := range optFns {
		fn(&opts)
	}

	ctx, cancel := context.WithCancel(context.Background())

	svc := &CTLogsService{
		options: opts,
		ctx:     ctx,
		cancel:  cancel,
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
			// Skip known placeholder or bogus logs (e.g., "Bogus placeholder log to unbreak misbehaving CT libraries")
			desc := strings.ToLower(logInfo.Description)
			if strings.Contains(desc, "bogus") || strings.Contains(desc, "placeholder") {
				continue
			}

			if logInfo.MMD > 86400 {
				continue
			}
			wg.Add(1)
			go service.processLogSource(initCtx, logInfo, &wg, &mu, &logCount)
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

// processLogSource handles initialization of a single CT log source.
// It is intended to run as a goroutine and will add the source to the
// service list if successful.
func (service *CTLogsService) processLogSource(ctx context.Context, logInfo CTLogInfo, wg *sync.WaitGroup, mu *sync.Mutex, logCount *int) {
	defer wg.Done()

	source, err := service.initLogSource(ctx, logInfo)
	if err != nil {
		gologger.Warning().Msgf("Skipping CT log source %s: %v", logInfo.Description, err)
		return
	}

	mu.Lock()
	service.sources = append(service.sources, source)
	*logCount++
	mu.Unlock()
}

// initLogSource sets up a CTLogSource for the given logInfo respecting the
// configured StartMode and returns it.
func (service *CTLogsService) initLogSource(ctx context.Context, logInfo CTLogInfo) (*CTLogSource, error) {
	client, err := NewCTLogClient(logInfo, WithHTTPClient(&http.Client{
		Timeout: 10 * time.Second,
	}))
	if err == nil {
		client.retryCounter = &service.backoffRetry
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create client for %s: %w", logInfo.Description, err)
	}

	sth, err := client.GetSTH(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get STH for %s: %w", logInfo.Description, err)
	}

	// Determine starting point based on configured StartMode / custom indices
	var startSize uint64
	switch service.options.StartMode {
	case StartBeginning:
		startSize = 0
	case StartCustom:
		sourceID := FormatSourceID(logInfo.Description)
		if idx, ok := service.options.CustomStartIndices[sourceID]; ok {
			startSize = idx
		} else {
			startSize = 0
		}
	case StartNow:
		fallthrough
	default:
		startSize = sth.TreeSize
	}

	if startSize > sth.TreeSize {
		startSize = sth.TreeSize
	}

	source := &CTLogSource{
		Client:     client,
		LastSize:   startSize,
		TreeSize:   sth.TreeSize, // Store initial tree size
		WindowSize: 1000,         // Process entries in chunks of 1000
	}
	return source, nil
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

	// Update source tree size with latest STH
	source.TreeSize = sth.TreeSize

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
		lag := sth.TreeSize - start
		gologger.Info().Msgf("[%s] Fetched %d entries (%d-%d), TreeSize: %d, Lag: %d", 
			source.Client.Info().Description, len(entries), start, end-1, sth.TreeSize, lag)
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

	service.totalCert.Add(1)
	if duplicate {
		service.duplicates.Add(1)
	} else {
		service.uniqueCert.Add(1)
	}

	// Process all certificates - no filtering
	if duplicate && service.options.Callback == nil {
		// Skip duplicates when using legacy channel approach.
		return nil
	}

	// Invoke callback if configured.
	if service.options.Callback != nil {
		clientInfo := source.Client.Info()
		lag := source.TreeSize - index
		
		meta := EntryMeta{
			SourceID:       service.formatSourceID(clientInfo.Description),
			SourceDesc:     clientInfo.Description,
			LogURL:         clientInfo.URL,
			Index:          index,
			TreeSize:       source.TreeSize,
			Lag:            lag,
			CollectionTime: time.Now(),
		}

		service.options.Callback(meta, cert.Raw, duplicate)
	}

	return nil
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

// Stats represents a snapshot of service metrics.
type Stats struct {
	Total      uint64 `json:"total"`
	Unique     uint64 `json:"unique"`
	Duplicates uint64 `json:"duplicates"`
	Retries    uint64 `json:"retries"`
}

// GetStats atomically captures current counters.
func (service *CTLogsService) GetStats() Stats {
	return Stats{
		Total:      service.totalCert.Load(),
		Unique:     service.uniqueCert.Load(),
		Duplicates: service.duplicates.Load(),
		Retries:    service.backoffRetry.Load(),
	}
}

// ConvertCertificateToResponse converts an x509 certificate to tlsx response
// format. It is exported so callers (e.g., CLI runner) can reuse the same
// mapping logic as the service internals.
func ConvertCertificateToResponse(cert *x509.Certificate, sourceName string, includeCert bool) *clients.Response {
	return ConvertCertificateToResponseWithMeta(cert, sourceName, includeCert, nil)
}

// ConvertCertificateToResponseWithMeta converts an x509 certificate to tlsx response
// format with optional CT log metadata.
func ConvertCertificateToResponseWithMeta(cert *x509.Certificate, sourceName string, includeCert bool, meta *EntryMeta) *clients.Response {
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
		SelfSigned:   clients.IsSelfSigned(cert.AuthorityKeyId, cert.SubjectKeyId, cert.DNSNames),
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
	if includeCert {
		certResp.Certificate = clients.PemEncode(cert.Raw)
	}

	// Create response
	response := &clients.Response{
		Timestamp:           &now,
		Host:                host,
		Port:                "443", // Default HTTPS port
		ProbeStatus:         true,
		CertificateResponse: certResp,
		CTLogSource:         FormatSourceID(sourceName),
	}

	// Add CT log metadata if provided
	if meta != nil {
		response.CTLogIndex = meta.Index
		response.CTLogTreeSize = meta.TreeSize
		response.CTLogLag = meta.Lag
	}

	return response
}
