# tlsx Issue #819 Patch Report

## Root Cause Hypothesis
- Primary hang cause: `ztls` timeout wrapper did not actually enforce timeout. In `pkg/tlsx/ztls/ztls.go`, `tlsConn.Handshake()` was executed inline inside a `select` send expression, so the call could block forever before `ctx.Done()` was checked.
- This can stall worker goroutines indefinitely for problematic hosts, which matches the issue symptoms.
- Truncated JSONL lines are likely a downstream effect when users terminate a hung scan mid-write.
- Secondary correctness bug: output file write errors were wrapped with the wrong variable (`err` instead of `writeErr`) in `pkg/output/output.go`, which could hide write failures.

## Changes
1. Fixed ztls handshake timeout behavior (`pkg/tlsx/ztls/ztls.go:324`)
- Run `tlsConn.Handshake()` in a goroutine and wait on either:
  - handshake completion, or
  - context deadline/cancel.
- On timeout, force-close `tlsConn` before returning timeout error to unblock any in-flight handshake.

2. Added regression test for handshake timeout (`pkg/tlsx/ztls/ztls_timeout_test.go:12`)
- New test uses `net.Pipe()` with an idle peer so handshake blocks.
- Asserts `tlsHandshakeWithTimeout` returns promptly on context deadline (instead of hanging).

3. Fixed output write error propagation (`pkg/output/output.go:94`)
- Changed `errkit.Wrap(err, ...)` to `errkit.Wrap(writeErr, ...)` so file write failures are not swallowed.

4. Added regression test for output write error propagation (`pkg/output/output_test.go:29`)
- Constructs a writer with a closed temp file and verifies `Write` returns an error.

## Validation Commands + Outputs
Executed from repo root (`/home/ubuntu/repos/personal_openclaw/workspace/bounties/tlsx`):

1. `go test ./pkg/tlsx/ztls -run TestTLSHandshakeWithTimeoutReturnsOnContextDeadline -count=1`
- Output:
  - `go: downloading go1.24.0 (linux/amd64)`
  - `go: download go1.24.0: ... permission denied` (initial cache path)

2. `GOPATH=/tmp/go GOMODCACHE=/tmp/go/pkg/mod GOCACHE=/tmp/go-build go test ./pkg/tlsx/ztls -run TestTLSHandshakeWithTimeoutReturnsOnContextDeadline -count=1`
- Output:
  - `go: downloading go1.24.0 (linux/amd64)`
  - `go: download go1.24.0: ... Get "https://proxy.golang.org/...": ... socket: operation not permitted`

3. `GOPATH=/tmp/go GOMODCACHE=/tmp/go/pkg/mod GOCACHE=/tmp/go-build go test ./...`
- Output:
  - same toolchain download/network restriction error as above.

4. `GOPATH=/tmp/go GOMODCACHE=/tmp/go/pkg/mod GOCACHE=/tmp/go-build go build ./cmd/tlsx`
- Output:
  - same toolchain download/network restriction error as above.

5. `gofmt -w pkg/output/output.go pkg/output/output_test.go pkg/tlsx/ztls/ztls.go pkg/tlsx/ztls/ztls_timeout_test.go`
- Output: success (no errors).

## Limitations
- Full test/build verification could not be completed in this sandbox because:
  - `go.mod` requires Go `1.24.0`,
  - local toolchain is `go1.22.2`,
  - automatic toolchain download is blocked by sandbox network restrictions.
- The patch is intentionally minimal and targeted to the identified indefinite-hang path in `ztls` plus one output error-propagation bug.
