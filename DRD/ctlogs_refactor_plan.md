# CT Logs Refactor & Enhancement Plan

This document tracks the work required to refactor the Certificate Transparency (CT) logs implementation.  It converts the original bullet-point list into a sequenced plan with clear milestones and check-list items.

---

## Goal

Provide a clean, testable and extensible CT logs SDK / CLI that offers:

* A dedicated, reusable `CTLogClient` responsible **only** for interacting with a single log endpoint.
* A redesigned `CTLogsService` that:
  * Manages multiple `CTLogClient` instances.
  * Performs duplicate filtering with an inverse bloom filter.
  * Exposes a callback-based streaming API.
  * Tracks rich, atomic metrics.
  * Handles rate-limiting via exponential back-off.
  * Supports flexible start-index semantics (beginning / now / custom).
* Fully covered by fast, deterministic unit tests.
* Minimal CLI changes (new start flags; everything else remains automatic).

---

## High-Level Milestones

| # | Milestone | Outcomes |
|---|-----------|----------|
| 1 | **Foundation & Interfaces** | • `CTLogClient` skeleton<br>• New `ServiceOptions` & `ClientOptions` (builder style)<br>• Updated `CTLogsService` skeleton using callback API |
| 2 | **Deduplication & Data Flow** | • Integrate `InverseBloomFilter`<br>• Replace channel-based output with callback( meta, cert, duplicate ) |
| 3 | **Rate-Limiting** | • Generic exponential back-off utility<br>• Integrated into `CTLogClient`<br>• Unit tests with time mocking |
| 4 | **Index Snapshot & Resume** | • Snapshot data model<br>• Logic to start at beginning / now / custom per-log<br>• CLI flags wired (`--ctl-beginning`, `--ctl-index`) |
| 5 | **Metrics, Polish & Docs** | • Atomic stats counters + getter<br>• Optional periodic stats logger<br>• Final lint / vet clean-up<br>• README / example updates |

---

## Detailed TODO Checklist

### Milestone 1 — Foundation & Interfaces  ✅

- [ ] Create `pkg/ctlogs/client.go` defining `CTLogClient`:
  - [ ] `Fetch(ctx) ([]*ct.LogEntry, error)`
  - [ ] Embedded exponential back-off logic (stub)
  - [ ] Internal stats structure
- [ ] Introduce `ClientOptions` (client-level) with builder pattern.
- [ ] Introduce `ServiceOptions` (service-level) with builder pattern — includes duplicates filter size, stats interval, start mode.
- [ ] Refactor `CTLogsService` to accept a `func(meta CTLogMeta, cert *x509.Certificate, duplicate bool)` callback instead of output channel.

### Milestone 2 — Deduplication & Data Flow  ✅

- [ ] Add dependency `github.com/tylertreat/InverseBloomFilter`.
- [ ] Instantiate a shared inverse bloom filter in `CTLogsService`.
- [ ] Generate uniqueness key: `issuerDN + serialNumber`.
- [ ] Before invoking callback, mark & look-up duplicate flag.
- [ ] Remove channel send logic & related tests.

### Milestone 3 — Rate-Limiting  ✅

- [ ] Implement `backoff.ExpBackoff` helper with configurable max.
- [ ] Integrate into `CTLogClient` HTTP fetch paths.
- [ ] Provide reasonable defaults; allow override via `ClientOptions`.
- [ ] Write unit tests using `clock` / stub time to ensure < 1 s runtime.

### Milestone 4 — Index Snapshot & Resume

- [ ] When initializing service, fetch log list once & store in resume structure.
- [ ] If `ServiceOptions.customSnapshot` provided, merge with fetched list.
- [ ] Support three start modes per source: `Beginning`, `Now (default)`, `CustomIndex`.
- [ ] Wire CLI flags to service options.

### Milestone 4 — Metrics / Stats  ✅

**Implemented:**
* Atomic counters in `CTLogsService` for total, unique, duplicates, retries.
* `GetStats` snapshot API.
* Counters wired into duplicate check and back-off retry path.

**Pain points / insights**
* Wiring retry stats required lightweight coupling between client and service (pointer injection) to avoid heavy refactor.
* Jitter in back-off makes deterministic testing tricky → allowed tolerance in unit tests rather than mocking rand.

### Milestone 5 — CLI Integration & Documentation  ✅

* Removed legacy channel interface from `CTLogsService` – callback is now the sole streaming mechanism.
* CLI (`tlsx`) re-wired to builder options + callback, adding flags:
  * `--ctl-beginning / -cb`
  * `--ctl-index / -ci`
* Runner adapts callback output into existing writer; behaviour unchanged for end-users.
* README updated with CT-Logs section and examples.
* Added public helper `ConvertCertificateToResponse` to share certificate→response mapping between service and CLI (prevents code duplication).

**Closing Notes**

The CT Logs subsystem is now fully decoupled, uses functional options throughout, offers deduplication, rate-limiting back-off, atomic metrics, and integrates cleanly with the CLI. Further enhancements (e.g., Prometheus exporter) can build atop the stats snapshot API without touching core logic.

---

_Last updated: <!-- @AUTODATE@ -->_