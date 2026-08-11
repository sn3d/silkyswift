package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sn3d/silkyswift/internal/ca"
	"github.com/sn3d/silkyswift/internal/recorder"
	"github.com/sn3d/silkyswift/internal/sample"
)

// syntheticReq is a minimal but realistic /v1/messages request body: a system
// prompt, a user turn, a prior assistant tool_use, and its tool_result — enough
// to exercise the full transform. No captured/PII data, so it is safe to commit.
const syntheticReq = `{
  "model": "claude-opus-4-6",
  "system": [{"type":"text","text":"You are a helpful assistant."}],
  "tools": [
    {"name":"Grep","description":"search","input_schema":{"type":"object","properties":{"pattern":{"type":"string"}}}}
  ],
  "messages": [
    {"role":"user","content":[{"type":"text","text":"find the config"}]},
    {"role":"assistant","content":[
      {"type":"text","text":"I'll search."},
      {"type":"tool_use","id":"toolu_seed","name":"Grep","input":{"pattern":"config"}}
    ]},
    {"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_seed","content":"config.yaml"}]}
  ]
}`

// syntheticSSE is a small captured-shape SSE stream: a text delta plus a
// tool_use assembled from split input_json_delta chunks.
const syntheticSSE = "event: message_start\n" +
	`data: {"type":"message_start","message":{"model":"claude-opus-4-6"}}` + "\n\n" +
	"event: content_block_start\n" +
	`data: {"type":"content_block_start","index":0,"content_block":{"type":"text"}}` + "\n\n" +
	"event: content_block_delta\n" +
	`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Found it. Reading now."}}` + "\n\n" +
	"event: content_block_stop\n" +
	`data: {"type":"content_block_stop","index":0}` + "\n\n" +
	"event: content_block_start\n" +
	`data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_final","name":"Grep"}}` + "\n\n" +
	"event: content_block_delta\n" +
	`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"pattern"}}` + "\n\n" +
	"event: content_block_delta\n" +
	`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"\":\"x\"}"}}` + "\n\n" +
	"event: message_delta\n" +
	`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"}}` + "\n\n" +
	"event: message_stop\n" +
	`data: {"type":"message_stop"}` + "\n\n"

// TestProxyHandler_EndToEnd drives a real /v1/messages request through the
// actual proxyHandler against a mock upstream that streams an SSE response,
// then asserts both the raw .txt and the messages .json sample are written
// correctly. Nothing external is contacted; the fixture is synthetic.
func TestProxyHandler_EndToEnd(t *testing.T) {
	reqBody := []byte(syntheticReq)
	sseBody := []byte(syntheticSSE)

	// Mock upstream: a TLS server (proxyHandler builds an https:// upstream URL)
	// serving the captured SSE body so the proxy takes its streaming+assemble
	// path. httptest mints a self-signed cert we trust via RootCAs below.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(sseBody)
	}))
	defer upstream.Close()
	upstreamHost := strings.TrimPrefix(upstream.URL, "https://") // 127.0.0.1:PORT

	// Trust the mock's cert and redirect the recorded host to it. The mock cert
	// is issued for "example.com"/127.0.0.1, so skip hostname verification while
	// still validating against its CA pool.
	certPool := x509.NewCertPool()
	certPool.AddCert(upstream.Certificate())
	transport := &http.Transport{
		DisableCompression: true,
		TLSClientConfig: &tls.Config{
			RootCAs:            certPool,
			InsecureSkipVerify: true, // mock cert CN != api.anthropic.com
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if strings.HasPrefix(addr, recordedHost+":") {
				addr = upstreamHost
			}
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
		},
	}

	dir := t.TempDir()
	rec, err := recorder.New(dir)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	srec, err := sample.New(dir)
	if err != nil {
		t.Fatalf("sample.New: %v", err)
	}

	// httptest mock speaks plain HTTP; make the handler build an http:// upstream
	// URL by pretending the recorded host over the redirected dial. We reach
	// proxyHandler directly (the CONNECT/TLS layer is orthogonal and unit-tested
	// elsewhere).
	h := proxyHandler(recordedHost, rec, srec, transport)

	// Build the client-facing request exactly as the TLS layer would hand it to
	// the handler: method POST, path /v1/messages, the captured body.
	req := httptest.NewRequest(http.MethodPost, "https://"+recordedHost+"/v1/messages?beta=true", strings.NewReader(string(reqBody)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("handler status = %d, want 200; body=%s", rr.Code, rr.Body.String()[:min(200, rr.Body.Len())])
	}

	// The sample is written off-thread (go srec.Record). Poll for the file.
	var samplePath string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		matches, _ := filepath.Glob(filepath.Join(dir, "*_sample.json"))
		if len(matches) == 1 {
			samplePath = matches[0]
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if samplePath == "" {
		entries, _ := os.ReadDir(dir)
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("no _sample.json written; dir has: %v", names)
	}

	data, err := os.ReadFile(samplePath)
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}
	var s sample.Sample
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("sample not valid JSON: %v", err)
	}

	// Assertions on the reconstructed sample.
	if s.Model == "" {
		t.Error("sample.Model empty")
	}
	if len(s.Tools) != 1 || s.Tools[0].Name != "Grep" {
		t.Errorf("tools = %+v, want one Grep tool", s.Tools)
	}
	// Expected reconstructed sequence:
	//   system, user, assistant(text+tool_calls), tool(result), assistant(assembled)
	wantRoles := []string{"system", "user", "assistant", "tool", "assistant"}
	if len(s.Messages) != len(wantRoles) {
		t.Fatalf("got %d messages, want %d: %+v", len(s.Messages), len(wantRoles), roles(s.Messages))
	}
	for i, want := range wantRoles {
		if s.Messages[i].Role != want {
			t.Errorf("message[%d] role = %q, want %q (seq %v)", i, s.Messages[i].Role, want, roles(s.Messages))
		}
	}
	// The tool message must be adjacent to (immediately follow) the assistant
	// tool_calls turn — the ordering fix from the code review.
	if s.Messages[2].Role == "assistant" && len(s.Messages[2].ToolCalls) == 0 {
		t.Error("assistant turn [2] lost its tool_calls")
	}
	if s.Messages[3].Role == "tool" && s.Messages[3].ToolCallID != "toolu_seed" {
		t.Errorf("tool msg tool_call_id = %q, want toolu_seed", s.Messages[3].ToolCallID)
	}
	// The final assembled assistant turn must carry the streamed text + tool call.
	last := s.Messages[len(s.Messages)-1]
	if last.Content == nil || *last.Content != "Found it. Reading now." {
		t.Errorf("assembled text = %v, want streamed text", last.Content)
	}
	if len(last.ToolCalls) != 1 || last.ToolCalls[0].Function.Arguments != `{"pattern":"x"}` {
		t.Errorf("assembled tool call = %+v, want Grep {\"pattern\":\"x\"}", last.ToolCalls)
	}
	// All tool-call arguments must be valid JSON.
	for _, m := range s.Messages {
		for _, tc := range m.ToolCalls {
			if !json.Valid([]byte(tc.Function.Arguments)) {
				t.Errorf("invalid tool args: %s", tc.Function.Arguments)
			}
		}
	}

	// The raw .txt pair must also exist (format=both semantics: both recorders
	// wired). Here both are non-nil, so raw response file should be present too.
	rawResp, _ := filepath.Glob(filepath.Join(dir, "*_resp.txt"))
	if len(rawResp) != 1 {
		t.Errorf("expected 1 raw _resp.txt, got %d", len(rawResp))
	}

	// Confirm the client saw the streamed SSE bytes forwarded through.
	if !strings.Contains(rr.Body.String(), "event:") {
		t.Error("client did not receive SSE stream")
	}

	t.Logf("E2E OK: model=%s messages=%d tools=%d sample=%dB",
		s.Model, len(s.Messages), len(s.Tools), len(data))
}

// TestServe_PlainHTTPPassthrough covers the regression where a plain-HTTP
// client routed through HTTPS_PROXY (e.g. a local http:// MCP server) was
// rejected with 405. The proxy must transparently forward such requests.
func TestServe_PlainHTTPPassthrough(t *testing.T) {
	// A plain-HTTP upstream standing in for a localhost MCP server.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tidewave/mcp" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("X-From-Upstream", "yes")
		_, _ = w.Write([]byte("mcp-ok"))
	}))
	defer upstream.Close()

	caDir := t.TempDir()
	authority, err := ca.LoadOrGenerate(filepath.Join(caDir, "ca.crt"), filepath.Join(caDir, "ca.key"))
	if err != nil {
		t.Fatalf("ca.LoadOrGenerate: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Bind an ephemeral port and run the real Serve loop (no recorders).
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	proxyAddr := ln.Addr().String()
	_ = ln.Close()

	go func() { _ = Serve(ctx, proxyAddr, authority, nil, nil) }()

	// Poll until the proxy is accepting.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, derr := net.Dial("tcp", proxyAddr)
		if derr == nil {
			_ = c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Drive a plain-HTTP proxy request just as an HTTPS_PROXY-aware client would:
	// absolute-form request-URI to the http:// upstream, sent to the proxy socket.
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	target := upstream.URL + "/tidewave/mcp"
	host := strings.TrimPrefix(upstream.URL, "http://")
	reqLine := "GET " + target + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(reqLine)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if resp.Header.Get("X-From-Upstream") != "yes" {
		t.Errorf("missing upstream header; got %v", resp.Header)
	}
	if string(body) != "mcp-ok" {
		t.Errorf("body = %q, want mcp-ok", body)
	}
}

// TestServe_PlainHTTPKeepAlive exercises the keep-alive loop in serveHTTP:
// two sequential plain-HTTP requests on one client connection must both be
// forwarded and answered, proving the loop reuses the socket rather than
// hanging or closing after the first response.
func TestServe_PlainHTTPKeepAlive(t *testing.T) {
	var hits int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		_, _ = io.WriteString(w, "reply-"+strconv.Itoa(int(n)))
	}))
	defer upstream.Close()

	caDir := t.TempDir()
	authority, err := ca.LoadOrGenerate(filepath.Join(caDir, "ca.crt"), filepath.Join(caDir, "ca.key"))
	if err != nil {
		t.Fatalf("ca.LoadOrGenerate: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	proxyAddr := ln.Addr().String()
	_ = ln.Close()

	go func() { _ = Serve(ctx, proxyAddr, authority, nil, nil) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, derr := net.Dial("tcp", proxyAddr)
		if derr == nil {
			_ = c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	host := strings.TrimPrefix(upstream.URL, "http://")
	br := bufio.NewReader(conn)

	// First request: keep-alive (no Connection: close).
	req1 := "GET " + upstream.URL + "/a HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
	if _, err := conn.Write([]byte(req1)); err != nil {
		t.Fatalf("write req1: %v", err)
	}
	resp1, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read resp1: %v", err)
	}
	body1, _ := io.ReadAll(resp1.Body)
	_ = resp1.Body.Close()
	if string(body1) != "reply-1" {
		t.Fatalf("resp1 body = %q, want reply-1", body1)
	}

	// Second request on the SAME connection must be served by the keep-alive loop.
	req2 := "GET " + upstream.URL + "/b HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req2)); err != nil {
		t.Fatalf("write req2: %v", err)
	}
	resp2, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read resp2 (keep-alive loop failed to serve 2nd request): %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if string(body2) != "reply-2" {
		t.Fatalf("resp2 body = %q, want reply-2", body2)
	}

	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("upstream hits = %d, want 2", got)
	}
}

func roles(msgs []sample.Message) []string {
	out := make([]string, len(msgs))
	for i, m := range msgs {
		out[i] = m.Role
	}
	return out
}
