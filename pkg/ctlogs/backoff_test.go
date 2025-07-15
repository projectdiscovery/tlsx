package ctlogs

import (
    "testing"
    "time"
)

func TestBackoffIncreasesAndCaps(t *testing.T) {
    base := 100 * time.Millisecond
    max := 1600 * time.Millisecond

    b := NewBackoff(base, max)

    d1 := b.Next()
    if d1 <= 0 || d1 > max {
        t.Fatalf("first duration invalid: %v", d1)
    }

    _ = b.Next() // advance once
    for i := 0; i < 10; i++ {
        next := b.Next()
        if next <= 0 {
            t.Fatalf("step %d produced non-positive duration", i)
        }
        if next > max {
            t.Fatalf("duration exceeded max: %v > %v", next, max)
        }
    }
}

func TestBackoffReset(t *testing.T) {
    base := 50 * time.Millisecond
    b := NewBackoff(base, 2*base)

    _ = b.Next()
    b.Reset()
    d := b.Next()
    if d <= 0 || d > 2*base {
        t.Fatalf("duration after reset unexpected: %v", d)
    }
}