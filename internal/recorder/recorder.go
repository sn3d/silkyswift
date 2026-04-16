// Package recorder writes intercepted HTTP request/response pairs to disk
// in raw HTTP wire format. Each pair produces two files in the target dir:
// YYYYMMDD-HHMMSSfff_NNNNN_req.txt and YYYYMMDD-HHMMSSfff_NNNNN_resp.txt.
package recorder

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Recorder owns a writable output directory.
type Recorder struct {
	dir string
}

// New creates the directory (MkdirAll) and verifies writability via a
// probe file, failing fast if the location is not usable.
func New(dir string) (*Recorder, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create recording dir %q: %w", dir, err)
	}
	probe := filepath.Join(dir, ".silkyswift-write-test")
	if err := os.WriteFile(probe, nil, 0644); err != nil {
		return nil, fmt.Errorf("recording dir %q not writable: %w", dir, err)
	}
	if err := os.Remove(probe); err != nil {
		return nil, fmt.Errorf("remove write-test probe %q: %w", probe, err)
	}
	return &Recorder{dir: dir}, nil
}

// Dir returns the output directory (for banner display).
func (r *Recorder) Dir() string {
	return r.dir
}

// MakePrefix builds "YYYYMMDD-HHMMSSfff_NNNNN" from a request id and timestamp.
func (r *Recorder) MakePrefix(id uint64, t time.Time) string {
	u := t.UTC()
	return fmt.Sprintf("%s%03d_%05d",
		u.Format("20060102-150405"),
		u.Nanosecond()/int(time.Millisecond),
		id,
	)
}

// WriteRequest writes `{prefix}_req.txt`. Errors are logged, never returned
// to the proxy hot path.
func (r *Recorder) WriteRequest(prefix, method, reqURI, proto, host string, headers http.Header, body []byte) {
	firstLine := fmt.Sprintf("%s %s %s", method, reqURI, proto)
	// Re-inject Host as the first header — Go moves it out of r.Header into
	// r.Host, but downstream tooling (curl/nc replay) expects it on the wire.
	buf := formatHead(firstLine, host, headers)
	buf = append(buf, body...)
	r.writeFile(prefix, "req", buf)
}

// WriteResponse writes `{prefix}_resp.txt` (non-streaming convenience).
func (r *Recorder) WriteResponse(prefix, proto string, status int, headers http.Header, body []byte) {
	firstLine := fmt.Sprintf("%s %d %s", proto, status, http.StatusText(status))
	buf := formatHead(firstLine, "", headers)
	buf = append(buf, body...)
	r.writeFile(prefix, "resp", buf)
}

// OpenResponseFile opens `{prefix}_resp.txt` for streaming writes. Caller
// writes the status line + headers via WriteResponseHead, then streams the
// body chunks, then Close()s.
func (r *Recorder) OpenResponseFile(prefix string) (*os.File, error) {
	path := filepath.Join(r.dir, prefix+"_resp.txt")
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
}

// WriteResponseHead writes the status line + headers + blank separator to f.
func WriteResponseHead(f *os.File, proto string, status int, headers http.Header) error {
	firstLine := fmt.Sprintf("%s %d %s", proto, status, http.StatusText(status))
	head := formatHead(firstLine, "", headers)
	_, err := f.Write(head)
	return err
}

func (r *Recorder) writeFile(prefix, kind string, data []byte) {
	path := filepath.Join(r.dir, fmt.Sprintf("%s_%s.txt", prefix, kind))
	if err := os.WriteFile(path, data, 0644); err != nil {
		slog.Warn("recorder write failed", "path", path, "err", err)
		return
	}
	slog.Info("recorded", "kind", kind, "path", path, "bytes", len(data))
}

// formatHead builds the request/status line + headers + blank CRLF. If
// hostInject is non-empty, a leading `Host: ...` header is emitted first
// (matches Rust recorder fidelity; Go strips Host from http.Header).
// Headers are written in sorted key order — http.Header map iteration is
// non-deterministic, and sorted output is easier to diff.
func formatHead(firstLine, hostInject string, headers http.Header) []byte {
	var buf bytes.Buffer
	buf.Grow(256 + len(headers)*48)
	buf.WriteString(firstLine)
	buf.WriteString("\r\n")

	if hostInject != "" {
		buf.WriteString("Host: ")
		buf.WriteString(hostInject)
		buf.WriteString("\r\n")
	}

	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range headers[k] {
			buf.WriteString(k)
			buf.WriteString(": ")
			buf.WriteString(v)
			buf.WriteString("\r\n")
		}
	}
	buf.WriteString("\r\n")
	return buf.Bytes()
}
