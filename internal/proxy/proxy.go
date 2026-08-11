// Package proxy implements a CONNECT-tunnel HTTPS intercepting proxy. For
// every accepted connection we parse one HTTP/1.1 request. A CONNECT upgrades
// the raw TCP socket to TLS using a per-SNI leaf cert minted by the CA and
// serves the decrypted traffic through an http.Server. Any other method is a
// plain-HTTP proxy request (absolute-form request-URI, e.g. a local http://
// MCP server routed through HTTPS_PROXY) and is forwarded transparently.
// Requests to api.anthropic.com/v1/* are recorded when a *recorder.Recorder
// is supplied; plain-HTTP is never the recorded endpoint.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sn3d/silkyswift/internal/ca"
	"github.com/sn3d/silkyswift/internal/recorder"
	"github.com/sn3d/silkyswift/internal/sample"
)

const (
	recordedHost       = "api.anthropic.com"
	recordedPathPrefix = "/v1/"
	// messagesPath is the only endpoint that yields a fine-tuning sample; other
	// /v1/* calls (mcp_servers, count_tokens, ...) are raw-recorded only.
	messagesPath = "/v1/messages"

	connectReadTimeout  = 10 * time.Second
	tlsHandshakeTimeout = 10 * time.Second
)

// hopByHopHeaders are connection-scoped and must not be forwarded between
// hops. Matches Rust SKIP_HEADERS semantics on the outbound copy.
var hopByHopHeaders = map[string]struct{}{
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Proxy-Connection":    {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

var requestCounter atomic.Uint64

// Serve binds to addr and accepts CONNECT requests until ctx is cancelled.
// rec may be nil (no recording).
func Serve(ctx context.Context, addr string, authority *ca.Authority, rec *recorder.Recorder, srec *sample.SampleRecorder) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	defer ln.Close()

	slog.Info("proxy listening", "addr", ln.Addr().String())

	transport := newUpstreamTransport()
	defer transport.CloseIdleConnections()

	// Close the listener when the context is cancelled so Accept returns.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			slog.Warn("accept error", "err", err)
			continue
		}
		go handleConn(conn, authority, rec, srec, transport)
	}
}

func handleConn(conn net.Conn, authority *ca.Authority, rec *recorder.Recorder, srec *sample.SampleRecorder, transport *http.Transport) {
	defer conn.Close()

	// Bound the CONNECT-read phase so slow clients can't tie up goroutines.
	_ = conn.SetReadDeadline(time.Now().Add(connectReadTimeout))

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if req.Method != http.MethodConnect {
		// Plain-HTTP proxy request (absolute-form request-URI, e.g. a local
		// http:// MCP server routed through HTTPS_PROXY). These are never the
		// recorded api.anthropic.com/v1/* endpoint (that arrives over CONNECT+TLS),
		// so forward transparently without recording. Clear the CONNECT-phase
		// deadline first; the plain-HTTP server sets its own timeouts.
		_ = conn.SetReadDeadline(time.Time{})
		serveHTTP(conn, br, req, transport)
		return
	}

	host := req.Host
	domain := host
	if i := strings.LastIndex(host, ":"); i >= 0 {
		domain = host[:i]
	}

	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	// Clear the CONNECT-phase deadline; TLS handshake has its own.
	_ = conn.SetReadDeadline(time.Time{})

	// bufio.Reader may have buffered bytes past the CONNECT request (the
	// start of the TLS ClientHello on pipelined clients). Wrap so those
	// bytes feed into the TLS handshake before falling through to conn.
	wrapped := &prefacedConn{Conn: conn, r: br}

	tlsConn := tls.Server(wrapped, &tls.Config{
		GetCertificate: authority.LeafFor,
	})

	hsCtx, cancel := context.WithTimeout(context.Background(), tlsHandshakeTimeout)
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		cancel()
		return
	}
	cancel()
	defer tlsConn.Close()

	srv := &http.Server{
		Handler:           proxyHandler(domain, rec, srec, transport),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	// Serve blocks until the client closes the TLS connection. The
	// single-conn listener is closed after the first accept so http.Server
	// shuts down cleanly when the TLS conn closes.
	_ = srv.Serve(newSingleConnListener(tlsConn))
}

// serveHTTP transparently forwards plain-HTTP proxy requests (absolute-form
// request-URI) over the same client connection, honoring HTTP/1.1 keep-alive.
// req is the first already-parsed request; further requests are read from br.
// No TLS, no recording — plain-HTTP is never the recorded endpoint.
//
// Like the CONNECT path, this forwards to any host the client names, which
// includes internal/link-local targets (cloud metadata, RFC1918). That open
// relay is only safe because the proxy is meant to bind loopback; do not
// expose the listener on a non-loopback address without an allowlist.
func serveHTTP(conn net.Conn, br *bufio.Reader, req *http.Request, transport *http.Transport) {
	for {
		keepAlive := forwardHTTPRequest(conn, req, transport)
		if !keepAlive {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		next, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Time{})
		req = next
	}
}

// forwardHTTPRequest proxies a single plain-HTTP request upstream and writes
// the response back to conn. It reports whether the connection may be reused
// for a subsequent keep-alive request.
func forwardHTTPRequest(conn net.Conn, req *http.Request, transport *http.Transport) bool {
	// Absolute-form request-URI carries the target; a proxy request without one
	// is malformed for our purposes.
	if req.URL == nil || req.URL.Host == "" {
		_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return false
	}

	// Capture the client's keep-alive intent before we reshape the request;
	// req.Close is reset below for the outbound hop.
	clientWantsClose := req.Close

	// Reshape the parsed server request into a client request the transport
	// accepts: RoundTrip rejects a non-empty RequestURI, and RequestURI/Close
	// carry no meaning outbound. Stream req.Body straight through (no buffering)
	// and keep req.URL verbatim so the target's path/query aren't re-encoded.
	defer req.Body.Close()
	req.RequestURI = ""
	req.Close = false
	for k := range req.Header {
		if isHopByHop(k) {
			req.Header.Del(k)
		}
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		slog.Warn("plain-http roundtrip error", "err", err)
		_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return false
	}
	defer resp.Body.Close()

	// Strip hop-by-hop headers on the client-facing copy, mirroring the CONNECT path.
	for k := range resp.Header {
		if isHopByHop(k) {
			resp.Header.Del(k)
		}
	}

	if err := resp.Write(conn); err != nil {
		return false
	}
	// resp.Write emits Connection: close semantics faithfully; reuse the conn
	// only when neither side asked to close.
	return !clientWantsClose && !resp.Close
}

func proxyHandler(domain string, rec *recorder.Recorder, srec *sample.SampleRecorder, transport *http.Transport) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := requestCounter.Add(1)

		// Buffer request body so we can both record it and resend upstream.
		var bodyBytes []byte
		if r.Body != nil {
			b, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read request body: "+err.Error(), http.StatusBadGateway)
				return
			}
			bodyBytes = b
			_ = r.Body.Close()
		}

		// A recorded endpoint is api.anthropic.com/v1/*. Raw and sample
		// recording are independent outputs; either being enabled recruits
		// the request into recording.
		isRecordedEndpoint := domain == recordedHost && strings.HasPrefix(r.URL.Path, recordedPathPrefix)
		recordRaw := rec != nil && isRecordedEndpoint
		// Samples are only meaningful for the Messages endpoint; other /v1/*
		// calls carry no conversation to fine-tune on.
		recordSample := srec != nil && domain == recordedHost && r.URL.Path == messagesPath
		shouldRecord := recordRaw || recordSample

		var (
			prefix  string
			reqTime time.Time
		)
		if shouldRecord {
			reqTime = time.Now()
			// Prefix scheme is owned by the raw recorder; reuse it when present
			// so raw .txt and .json share a prefix, else derive it locally.
			if rec != nil {
				prefix = rec.MakePrefix(reqID, reqTime)
			} else {
				prefix = makePrefix(reqID, reqTime)
			}
		}
		if recordRaw {
			// Fire request recording off-thread so disk I/O can't block forwarding.
			go rec.WriteRequest(
				prefix,
				r.Method,
				r.URL.RequestURI(),
				r.Proto,
				domain,
				r.Header.Clone(),
				bodyBytes,
			)
		}

		// Build the upstream request. Preserve method, headers, body; fix URL
		// so the transport knows to TLS-dial the real host.
		upstreamURL := *r.URL
		upstreamURL.Scheme = "https"
		upstreamURL.Host = domain

		upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL.String(), bytes.NewReader(bodyBytes))
		if err != nil {
			http.Error(w, "build upstream request: "+err.Error(), http.StatusBadGateway)
			return
		}
		for k, vs := range r.Header {
			// Strip any client-sent Accept-Encoding so upstream returns
			// uncompressed bytes that match what we record.
			if strings.EqualFold(k, "Accept-Encoding") {
				continue
			}
			for _, v := range vs {
				upstreamReq.Header.Add(k, v)
			}
		}
		upstreamReq.Host = domain

		resp, err := transport.RoundTrip(upstreamReq)
		if err != nil {
			slog.Warn("upstream roundtrip error", "err", err)
			http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		// Copy response headers, stripping hop-by-hop on the client-facing copy.
		for k, vs := range resp.Header {
			if isHopByHop(k) {
				continue
			}
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}

		isSSE := strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream")

		// Two streaming cases and one buffered case:
		//   - SSE (record or passthrough): stream + flush per chunk.
		//   - Non-SSE with recording: buffer + write file + forward.
		//   - Non-SSE without recording: pure passthrough (io.Copy).
		if isSSE {
			var recFile *os.File
			if recordRaw {
				f, err := rec.OpenResponseFile(prefix)
				if err != nil {
					slog.Warn("open response file", "err", err)
				} else {
					if err := recorder.WriteResponseHead(f, resp.Proto, resp.StatusCode, resp.Header); err != nil {
						slog.Warn("write response head", "err", err)
					}
					recFile = f
					defer func() {
						path := f.Name()
						_ = f.Close()
						if fi, err := os.Stat(path); err == nil {
							slog.Info("recorded", "kind", "resp", "path", path, "bytes", fi.Size(), "streamed", true)
						}
					}()
				}
			}
			var assembler *sample.Assembler
			if recordSample {
				assembler = sample.NewAssembler()
			}
			streamResponse(w, resp, recFile, assembler)
			if recordSample {
				msg, truncated := assembler.Done()
				// Record off-thread so parse/marshal/disk I/O stay off the
				// forwarding path.
				go srec.Record(prefix, reqTime, bodyBytes, msg, truncated)
			}
			return
		}

		if shouldRecord {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				slog.Warn("read upstream body", "err", err)
			}
			if recordRaw {
				// Pass upstream headers verbatim (hop-by-hop included) to the
				// recorder; the client-facing copy above is already filtered.
				go rec.WriteResponse(prefix, resp.Proto, resp.StatusCode, resp.Header.Clone(), body)
			}
			if recordSample {
				msg, ok := sample.AssembleJSON(body)
				if !ok {
					msg = nil
				}
				go srec.Record(prefix, reqTime, bodyBytes, msg, false)
			}
			w.WriteHeader(resp.StatusCode)
			_, _ = w.Write(body)
			return
		}

		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
}

// streamResponse copies resp.Body to w in real time, flushing after every
// read so SSE clients observe deltas as they arrive. If recFile is non-nil,
// each chunk is also written to the open recording file. On a client-write
// error, an SSE-comment truncation marker is appended to the recording so
// partial captures are self-describing.
func streamResponse(w http.ResponseWriter, resp *http.Response, recFile *os.File, assembler *sample.Assembler) {
	w.WriteHeader(resp.StatusCode)
	flusher, ok := w.(http.Flusher)
	if !ok {
		slog.Warn("responseWriter is not a Flusher; SSE output may buffer")
	}

	buf := make([]byte, 32*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if _, err := w.Write(chunk); err != nil {
				if recFile != nil {
					appendTruncationMarker(recFile, err.Error())
				}
				if assembler != nil {
					assembler.Truncate()
				}
				return
			}
			if recFile != nil {
				if _, err := recFile.Write(chunk); err != nil {
					slog.Warn("write chunk to recording", "err", err)
				}
			}
			if assembler != nil {
				assembler.Write(chunk)
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) && recFile != nil {
				appendTruncationMarker(recFile, readErr.Error())
			}
			if !errors.Is(readErr, io.EOF) && assembler != nil {
				assembler.Truncate()
			}
			return
		}
	}
}

// makePrefix builds the recorder prefix scheme locally for the sample-only
// path where no raw recorder is present to own it. Mirrors recorder.MakePrefix.
func makePrefix(id uint64, t time.Time) string {
	u := t.UTC()
	return fmt.Sprintf("%s%03d_%05d",
		u.Format("20060102-150405"),
		u.Nanosecond()/int(time.Millisecond),
		id,
	)
}

func appendTruncationMarker(f *os.File, msg string) {
	_, _ = fmt.Fprintf(f, "\n: [silkyswift: %s]\n\n", msg)
}

func isHopByHop(name string) bool {
	_, ok := hopByHopHeaders[http.CanonicalHeaderKey(name)]
	return ok
}

func newUpstreamTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig:    &tls.Config{},
		DisableCompression: true,
		// Disable HTTP/2 to match the Rust implementation (hyper http1 only).
		// Setting ForceAttemptHTTP2 to false alone is insufficient on modern
		// Go; an explicit empty TLSNextProto prevents h2 negotiation.
		ForceAttemptHTTP2: false,
		TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConnsPerHost: 10,
	}
}

// prefacedConn serves any bytes already buffered in r before falling
// through to the underlying Conn. Required because bufio.Reader may have
// read past the CONNECT request into the client's TLS ClientHello.
// After the handshake completes, the TLS stack drains r once and then
// reads directly from Conn.
type prefacedConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *prefacedConn) Read(b []byte) (int, error) {
	if p.r.Buffered() > 0 {
		return p.r.Read(b)
	}
	return p.Conn.Read(b)
}

// singleConnListener hands out one pre-accepted conn exactly once, then
// blocks further Accept calls until Close, at which point it returns
// io.EOF so http.Server.Serve can shut down cleanly.
type singleConnListener struct {
	conn net.Conn
	done chan struct{}
	once atomic.Bool
}

func newSingleConnListener(c net.Conn) *singleConnListener {
	return &singleConnListener{conn: c, done: make(chan struct{})}
}

func (s *singleConnListener) Accept() (net.Conn, error) {
	if s.once.CompareAndSwap(false, true) {
		return s.conn, nil
	}
	<-s.done
	return nil, io.EOF
}

func (s *singleConnListener) Close() error {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	return nil
}

func (s *singleConnListener) Addr() net.Addr {
	return s.conn.LocalAddr()
}
