package ctlogs

import "time"

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
	TreeSize   uint64 // Current tree size from latest STH
	WindowSize uint64 // Sliding window size
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
	SourceID       string    // normalized source identifier
	SourceDesc     string    // human-readable log description
	LogURL         string    // CT log URL for identification
	Index          uint64    // leaf index within the log
	TreeSize       uint64    // total number of entries in the log (head)
	Lag            uint64    // number of pending entries (TreeSize - Index)
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

	// Size of the inverse bloom filter (number of buckets).
	// Larger values reduce false negatives. Default 1,000,000.
	DedupeSize int

	// Stream start behaviour.
	StartMode          StartMode
	CustomStartIndices map[string]uint64 // by log URL or ID

	Callback EntryCallback
}

// defaultServiceOptions returns a fully-initialised set of defaults.
func defaultServiceOptions() ServiceOptions {
	return ServiceOptions{
		Verbose:            false,
		Cert:               false,
		PollInterval:       5 * time.Second,
		DedupeSize:         1_000_000,
		StartMode:          StartNow,
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

// WithCustomStartIndices sets multiple custom start indices at once and marks
// the StartMode as StartCustom.
func WithCustomStartIndices(m map[string]uint64) ServiceOption {
	return func(o *ServiceOptions) {
		if len(m) == 0 {
			return
		}
		o.StartMode = StartCustom
		if o.CustomStartIndices == nil {
			o.CustomStartIndices = make(map[string]uint64)
		}
		for k, v := range m {
			o.CustomStartIndices[k] = v
		}
	}
}

func WithCallback(cb EntryCallback) ServiceOption {
	return func(o *ServiceOptions) { o.Callback = cb }
}

// WithDedupeSize sets the size of the inverse bloom filter.
func WithDedupeSize(sz int) ServiceOption {
	return func(o *ServiceOptions) {
		if sz > 0 {
			o.DedupeSize = sz
		}
	}
}
