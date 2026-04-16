# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

SilkySwift is a minimal CONNECT-tunnel HTTPS intercepting proxy in Go. It records raw HTTP wire-format pairs for `api.anthropic.com/v1/*` traffic. **Stdlib only — zero external dependencies.** Do not introduce third-party modules.

## Commands

```bash
go build -o silkyswift .                    # build
go build -ldflags="-s -w" -o silkyswift .   # stripped build
go vet ./...                                 # vet
go test ./...                                # run all tests
go test ./internal/proxy -run TestName      # run a single test
```

Run locally:
```bash
./silkyswift --listen 127.0.0.1:8080 --record ./recordings
```
First run generates `ca.crt` / `ca.key` in the working directory; both are reused on subsequent runs and gitignored.

Exercise end-to-end against Claude Code:
```bash
HTTPS_PROXY=http://127.0.0.1:8080 NODE_EXTRA_CA_CERTS=$(pwd)/ca.crt claude -p "say hi"
```

## Architecture

The pipeline is three cooperating packages under `internal/`, composed once in `main.go` at the repo root:

1. **`internal/ca`** — `Authority` owns the root CA (ECDSA P-256). `LoadOrGenerate` reuses an on-disk PEM pair if the cert is a CA and its public key matches the loaded private key, otherwise writes fresh `ca.crt` (0644) / `ca.key` (0600). `LeafFor` implements `tls.Config.GetCertificate`: mints a per-SNI leaf cert on first miss and caches by domain under a mutex. Leaves are valid 1 year.

2. **`internal/proxy`** — `Serve` accepts TCP, reads one HTTP/1.1 `CONNECT` request, writes `200 Connection Established`, then upgrades the socket to TLS using `Authority.LeafFor`. Critical subtlety: `bufio.Reader` used to parse CONNECT may have already buffered the client's TLS ClientHello, so the raw conn is wrapped in `prefacedConn` which drains buffered bytes first. A `singleConnListener` feeds the one accepted conn into an `http.Server` so the stdlib HTTP handler can serve the decrypted stream. The handler:
   - Buffers the request body so it can both record and resend upstream.
   - Only records when `rec != nil && domain == api.anthropic.com && path starts with /v1/`; everything else is transparent passthrough.
   - Strips client `Accept-Encoding` so upstream returns uncompressed bytes that match what is recorded.
   - Three response paths: **SSE** (stream + flush per chunk, optionally tee to recording file), **non-SSE with recording** (buffer → file + forward), **non-SSE without recording** (pure `io.Copy`).
   - Strips hop-by-hop headers (`hopByHopHeaders` map) on the client-facing copy only; the recorder sees upstream headers verbatim.
   - Upstream transport explicitly disables HTTP/2 (empty `TLSNextProto` + `ForceAttemptHTTP2: false`) to mirror the original Rust/hyper http1 implementation.

3. **`internal/recorder`** — Writes two files per pair: `YYYYMMDD-HHMMSSfff_NNNNN_{req,resp}.txt`. `MakePrefix` produces the shared timestamp+counter prefix. `WriteRequest` / `WriteResponse` are the non-streaming path and are invoked on a goroutine from the proxy hot path (errors logged, not propagated). `OpenResponseFile` + `WriteResponseHead` + per-chunk writes is the SSE streaming path. `formatHead` writes headers in **sorted** key order (deterministic diffs) and re-injects `Host:` as the first header because Go's `net/http` moves it out of `Header` into `Request.Host` — downstream replay via curl/nc expects it on the wire. If a client write fails mid-stream, an SSE-comment truncation marker (`: [silkyswift: ...]`) is appended so partial captures are self-describing.

### Invariants to preserve when editing

- Stdlib only. No new imports outside the Go standard library.
- Do not introduce HTTP/2 on the upstream transport — recordings assume http1 framing.
- Keep disk I/O off the forwarding path: non-streaming recorder writes are `go`-dispatched.
- Recording scope is intentionally narrow (`api.anthropic.com` + `/v1/` prefix). Widening it changes the product surface — ask before doing so.
- Header ordering in recordings is canonicalized (`http.CanonicalHeaderKey`) and sorted; don't change without updating the rationale.

## Go / style notes specific to this repo

- Go 1.25, `go.mod` module path is `github.com/sn3d/silkyswift` (imports use `github.com/sn3d/silkyswift/internal/...`). `main.go` lives at the repo root — no `./cmd/` indirection.
- Errors are wrapped with `fmt.Errorf("...: %w", err)` at package boundaries; the proxy hot path logs and returns `502` rather than propagating.
- Timeouts are explicit constants (`connectReadTimeout`, `tlsHandshakeTimeout`, `ReadHeaderTimeout`, `IdleTimeout`) — preserve them when refactoring.
