package sample

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAssembler_TextAndToolUse(t *testing.T) {
	tests := []struct {
		name         string
		stream       string
		wantModel    string
		wantStop     string
		wantText     string
		wantTools    []ToolFunction
		wantTruncate bool
	}{
		{
			name: "text only",
			stream: sse(
				`{"type":"message_start","message":{"model":"claude-opus-4-6"}}`,
				`{"type":"content_block_start","index":0,"content_block":{"type":"text"}}`,
				`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello, "}}`,
				`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"world"}}`,
				`{"type":"content_block_stop","index":0}`,
				`{"type":"message_delta","delta":{"stop_reason":"end_turn"}}`,
				`{"type":"message_stop"}`,
			),
			wantModel: "claude-opus-4-6",
			wantStop:  "end_turn",
			wantText:  "Hello, world",
		},
		{
			name: "tool use with split input_json_delta",
			stream: sse(
				`{"type":"message_start","message":{"model":"claude-opus-4-6"}}`,
				`{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_01","name":"Grep"}}`,
				`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"pattern"}}`,
				`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"\":\"foo\"}"}}`,
				`{"type":"content_block_stop","index":0}`,
				`{"type":"message_delta","delta":{"stop_reason":"tool_use"}}`,
			),
			wantModel: "claude-opus-4-6",
			wantStop:  "tool_use",
			wantTools: []ToolFunction{{Name: "Grep", Arguments: `{"pattern":"foo"}`}},
		},
		{
			name: "text then tool_use, two blocks",
			stream: sse(
				`{"type":"message_start","message":{"model":"m"}}`,
				`{"type":"content_block_start","index":0,"content_block":{"type":"text"}}`,
				`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Let me look."}}`,
				`{"type":"content_block_stop","index":0}`,
				`{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_02","name":"Bash"}}`,
				`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"ls\"}"}}`,
				`{"type":"content_block_stop","index":1}`,
			),
			wantModel: "m",
			wantText:  "Let me look.",
			wantTools: []ToolFunction{{Name: "Bash", Arguments: `{"command":"ls"}`}},
		},
		{
			name: "truncation marker sets flag",
			stream: sse(
				`{"type":"message_start","message":{"model":"m"}}`,
				`{"type":"content_block_start","index":0,"content_block":{"type":"text"}}`,
				`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"partial"}}`,
			) + "\n: [silkyswift: connection reset]\n\n",
			wantModel:    "m",
			wantText:     "partial",
			wantTruncate: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAssembler()
			// Feed in small chunks to exercise mid-line splitting.
			for _, chunk := range chunkize(tt.stream, 7) {
				a.Write([]byte(chunk))
			}
			msg, truncated := a.Done()

			if msg.Model != tt.wantModel {
				t.Errorf("model = %q, want %q", msg.Model, tt.wantModel)
			}
			if msg.StopReason != tt.wantStop {
				t.Errorf("stop = %q, want %q", msg.StopReason, tt.wantStop)
			}
			if truncated != tt.wantTruncate {
				t.Errorf("truncated = %v, want %v", truncated, tt.wantTruncate)
			}

			m := msg.toMessage()
			gotText := ""
			if m.Content != nil {
				gotText = *m.Content
			}
			if gotText != tt.wantText {
				t.Errorf("text = %q, want %q", gotText, tt.wantText)
			}
			if len(m.ToolCalls) != len(tt.wantTools) {
				t.Fatalf("tool calls = %d, want %d", len(m.ToolCalls), len(tt.wantTools))
			}
			for i, want := range tt.wantTools {
				got := m.ToolCalls[i].Function
				if got.Name != want.Name || got.Arguments != want.Arguments {
					t.Errorf("tool[%d] = %+v, want %+v", i, got, want)
				}
				if m.ToolCalls[i].Type != "function" {
					t.Errorf("tool[%d].Type = %q, want function", i, m.ToolCalls[i].Type)
				}
				// Arguments must be valid JSON.
				if !json.Valid([]byte(got.Arguments)) {
					t.Errorf("tool[%d].Arguments not valid JSON: %s", i, got.Arguments)
				}
			}
		})
	}
}

func TestAssembleJSON(t *testing.T) {
	body := `{"model":"claude-opus-4-6","stop_reason":"end_turn","content":[` +
		`{"type":"text","text":"hi"},` +
		`{"type":"tool_use","id":"toolu_9","name":"Read","input":{"path":"/x"}}]}`
	msg, ok := AssembleJSON([]byte(body))
	if !ok {
		t.Fatal("AssembleJSON failed")
	}
	m := msg.toMessage()
	if m.Content == nil || *m.Content != "hi" {
		t.Errorf("content = %v, want hi", m.Content)
	}
	if len(m.ToolCalls) != 1 || m.ToolCalls[0].Function.Name != "Read" {
		t.Fatalf("tool calls = %+v", m.ToolCalls)
	}
	if m.ToolCalls[0].Function.Arguments != `{"path":"/x"}` {
		t.Errorf("args = %q", m.ToolCalls[0].Function.Arguments)
	}
}

// sse joins data payloads into an SSE stream with event lines and blank
// separators, mirroring the Anthropic wire format.
func sse(payloads ...string) string {
	var b strings.Builder
	for _, p := range payloads {
		var e struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal([]byte(p), &e)
		b.WriteString("event: ")
		b.WriteString(e.Type)
		b.WriteString("\ndata: ")
		b.WriteString(p)
		b.WriteString("\n\n")
	}
	return b.String()
}

func chunkize(s string, n int) []string {
	var out []string
	for i := 0; i < len(s); i += n {
		end := min(i+n, len(s))
		out = append(out, s[i:end])
	}
	return out
}
