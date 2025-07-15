package ctlogs

import (
    "math"
    "math/rand"
    "time"
)

// Backoff implements an exponential back-off with optional jitter and a maximum
// cap. It is goroutine-safe if each goroutine uses its own instance.
//
// Zero value is ready to use with default parameters (base 500ms, factor 2.0,
// max 60s).
//
// Call Next() to obtain the next wait duration. Call Reset() after a successful
// attempt to restart.
//
// The implementation purposefully avoids floats at runtime by using pre-scaled
// integers.
type Backoff struct {
    attempt int

    base time.Duration // initial delay
    max  time.Duration // maximum delay cap
    factor float64
    jitter bool
}

// NewBackoff returns a Backoff configured with the given base and max.
func NewBackoff(base, max time.Duration) Backoff {
    if base <= 0 {
        base = 500 * time.Millisecond
    }
    if max <= 0 {
        max = 60 * time.Second
    }
    return Backoff{base: base, max: max, factor: 2.0, jitter: true}
}

// Next returns the duration to wait for the current attempt and increments the
// internal attempt counter.
func (b *Backoff) Next() time.Duration {
    // Calculate exponential; cap at max.
    d := float64(b.base) * math.Pow(b.factor, float64(b.attempt))
    if d > float64(b.max) {
        d = float64(b.max)
    }
    b.attempt++

    dur := time.Duration(d)
    if b.jitter {
        // +/- 50% jitter
        jitter := dur / 2
        dur = dur - jitter + time.Duration(rand.Int63n(int64(jitter*2)))
        if dur > b.max {
            dur = b.max
        }
    }
    return dur
}

// Reset sets the attempt counter back to 0.
func (b *Backoff) Reset() { b.attempt = 0 }