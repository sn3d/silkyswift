package sample

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// SampleRecorder owns a writable output directory and writes one
// {prefix}_sample.json per recorded request/response pair.
type SampleRecorder struct {
	dir string
}

// New creates the directory (MkdirAll) and verifies writability via a probe
// file, failing fast if the location is not usable. Mirrors recorder.New so a
// single --record dir hosts both raw .txt and .json outputs.
func New(dir string) (*SampleRecorder, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create sample dir %q: %w", dir, err)
	}
	probe := filepath.Join(dir, ".silkyswift-sample-write-test")
	if err := os.WriteFile(probe, nil, 0644); err != nil {
		return nil, fmt.Errorf("sample dir %q not writable: %w", dir, err)
	}
	if err := os.Remove(probe); err != nil {
		return nil, fmt.Errorf("remove sample write-test probe %q: %w", probe, err)
	}
	return &SampleRecorder{dir: dir}, nil
}

// Dir returns the output directory (for banner display).
func (r *SampleRecorder) Dir() string { return r.dir }

// Record parses the request body, folds in the assembled response, and writes
// {prefix}_sample.json. Errors are logged, never returned to the hot path.
// ts is the request timestamp; truncated marks a partial response stream.
func (r *SampleRecorder) Record(prefix string, ts time.Time, reqBody []byte, assembled *AssembledMessage, truncated bool) {
	var req anthReq
	if err := json.Unmarshal(reqBody, &req); err != nil {
		slog.Warn("sample parse request failed", "prefix", prefix, "err", err)
		return
	}

	model := req.Model
	if assembled != nil && assembled.Model != "" {
		model = assembled.Model
	}

	s := Sample{
		ID:        prefix,
		TS:        ts.UTC().Format(time.RFC3339Nano),
		Model:     model,
		Tools:     convertTools(req.Tools),
		Messages:  buildMessages(&req, assembled),
		Truncated: truncated,
	}

	data, err := json.Marshal(s)
	if err != nil {
		slog.Warn("sample marshal failed", "prefix", prefix, "err", err)
		return
	}

	path := filepath.Join(r.dir, prefix+"_sample.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		slog.Warn("sample write failed", "path", path, "err", err)
		return
	}
	slog.Info("recorded sample", "path", path, "messages", len(s.Messages), "bytes", len(data))
}
