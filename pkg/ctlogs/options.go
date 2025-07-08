package ctlogs

import "time"

// StartMode defines where the service should begin streaming from.
//
// Beginning: from index 0
// Now: from log's current tree size (default)
// Custom: per-log custom indices provided by the caller.
type StartMode int

const (
    StartNow StartMode = iota // default behaviour
    StartBeginning
    StartCustom
)

// EntryMeta carries minimal contextual information about a log entry passed
// to the callback.
type EntryMeta struct {
    SourceID       string // normalized source identifier
    SourceDesc     string // human-readable log description
    Index          uint64 // leaf index within the log
    CollectionTime time.Time
}

// EntryCallback is invoked for every certificate observed (after dedup phase).
//
// duplicate indicates whether the certificate is *likely* a duplicate according
// to the inverse bloom filter (always false before Milestone 2).
type EntryCallback func(meta EntryMeta, certData []byte, duplicate bool)

// ServiceOptions configures a CTLogsService instance.
//
// The struct should remain stable; always prefer adding new functional option
// helpers instead of exposing fields.
//
//nolint:revive // public fields kept for clarity and json tags are not needed.
type ServiceOptions struct {
    Verbose bool
    Cert    bool // include PEM in callback

    PollInterval time.Duration

    // Stream start behaviour.
    StartMode          StartMode
    CustomStartIndices map[string]uint64 // by log URL or ID

    Callback EntryCallback
}

// defaultServiceOptions returns a fully-initialised set of defaults.
func defaultServiceOptions() ServiceOptions {
    return ServiceOptions{
        Verbose:     false,
        Cert:        false,
        PollInterval: 5 * time.Second,
        StartMode:   StartNow,
        CustomStartIndices: make(map[string]uint64),
    }
}

// ServiceOption mutates a ServiceOptions instance.
type ServiceOption func(*ServiceOptions)

func WithVerbose(v bool) ServiceOption {
    return func(o *ServiceOptions) { o.Verbose = v }
}

func WithCert(c bool) ServiceOption {
    return func(o *ServiceOptions) { o.Cert = c }
}

func WithPollInterval(d time.Duration) ServiceOption {
    return func(o *ServiceOptions) { o.PollInterval = d }
}

func WithStartBeginning() ServiceOption {
    return func(o *ServiceOptions) { o.StartMode = StartBeginning }
}

func WithStartNow() ServiceOption {
    return func(o *ServiceOptions) { o.StartMode = StartNow }
}

// WithCustomStartIndex sets a starting index for a specific log (by URL or ID).
// Automatically sets StartMode to StartCustom.
func WithCustomStartIndex(logID string, idx uint64) ServiceOption {
    return func(o *ServiceOptions) {
        o.StartMode = StartCustom
        if o.CustomStartIndices == nil {
            o.CustomStartIndices = make(map[string]uint64)
        }
        o.CustomStartIndices[logID] = idx
    }
}

func WithCallback(cb EntryCallback) ServiceOption {
    return func(o *ServiceOptions) { o.Callback = cb }
}