package ctlogs

import (
	"context"
	"net/http"
	"sync/atomic"
	"time"

	ct "github.com/google/certificate-transparency-go"
	ctclient "github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
)

// ClientOptions controls behaviour of a CTLogClient.
// All fields are optional – sensible defaults are applied when a value is not
// supplied.
type ClientOptions struct {
	// HTTPClient used for all outbound requests.
	HTTPClient *http.Client

	// MaxBackoff caps the exponential back-off duration (future milestone).
	MaxBackoff time.Duration

	// Sleep allows overriding the sleep behaviour (useful for testing).
	Sleep func(time.Duration)
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(c *http.Client) func(*ClientOptions) {
	return func(o *ClientOptions) {
		o.HTTPClient = c
	}
}

// WithMaxBackoff customises the back-off ceiling (placeholder).
func WithMaxBackoff(d time.Duration) func(*ClientOptions) {
	return func(o *ClientOptions) {
		o.MaxBackoff = d
	}
}

// WithSleepFn customises the sleep function.
func WithSleepFn(sleepFn func(time.Duration)) func(*ClientOptions) {
	return func(o *ClientOptions) { o.Sleep = sleepFn }
}

// applyDefaults initialises zero-value fields of ClientOptions.
func (o *ClientOptions) applyDefaults() {
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if o.MaxBackoff == 0 {
		o.MaxBackoff = 60 * time.Second
	}
	if o.Sleep == nil {
		o.Sleep = time.Sleep
	}
}

// CTLogClient is a thin wrapper over certificate-transparency-go's LogClient
// with room for future enhancements such as rate-limiting/back-off, statistics
// and instrumentation. It is safe for concurrent use.
type CTLogClient struct {
	info   CTLogInfo
	client *ctclient.LogClient
	opts   ClientOptions

	retryCounter *atomic.Uint64
}

// NewCTLogClient constructs a CTLogClient for the provided log definition.
// Option functions may be passed to modify behaviour.
func NewCTLogClient(info CTLogInfo, optFns ...func(*ClientOptions)) (*CTLogClient, error) {
	var opts ClientOptions
	for _, fn := range optFns {
		fn(&opts)
	}
	opts.applyDefaults()

	lc, err := ctclient.New(info.URL, opts.HTTPClient, jsonclient.Options{})
	if err != nil {
		return nil, err
	}

	return &CTLogClient{
		info:   info,
		client: lc,
		opts:   opts,
	}, nil
}

// Info returns metadata describing the CT log this client is connected to.
func (c *CTLogClient) Info() CTLogInfo {
	return c.info
}

// GetSTH fetches the latest Signed Tree Head.
func (c *CTLogClient) GetSTH(ctx context.Context) (*ct.SignedTreeHead, error) {
	return c.client.GetSTH(ctx)
}

// GetEntries retrieves entries in the inclusive range [start, end].
func (c *CTLogClient) GetEntries(ctx context.Context, start, end uint64) ([]ct.LogEntry, error) {
	backoff := NewBackoff(500*time.Millisecond, c.opts.MaxBackoff)

	for {
		entries, err := c.client.GetEntries(ctx, int64(start), int64(end))
		if err == nil {
			backoff.Reset()
			return entries, nil
		}

		// If context is done, propagate.
		if ctx.Err() != nil {
			return nil, err
		}

		if c.retryCounter != nil {
			c.retryCounter.Add(1)
		}

		// Wait then retry.
		wait := backoff.Next()
		c.opts.Sleep(wait)
	}
}
