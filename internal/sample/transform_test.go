package sample

import (
	"encoding/json"
	"testing"
)

func TestSystemText(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"string", `"you are helpful"`, "you are helpful"},
		{"list of text blocks", `[{"type":"text","text":"a"},{"type":"text","text":"b"}]`, "a\nb"},
		{"empty", ``, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := systemText(json.RawMessage(tt.in)); got != tt.want {
				t.Errorf("systemText = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConvertMessage_ToolResult(t *testing.T) {
	// A user message carrying only tool_result blocks becomes role:"tool"
	// messages, not a user turn.
	m := &anthMessage{
		Role:    "user",
		Content: json.RawMessage(`[{"type":"tool_result","tool_use_id":"toolu_1","content":"result text"}]`),
	}
	got := convertMessage(m)
	if len(got) != 1 {
		t.Fatalf("got %d messages, want 1", len(got))
	}
	if got[0].Role != "tool" || got[0].ToolCallID != "toolu_1" {
		t.Errorf("msg = %+v", got[0])
	}
	if got[0].Content == nil || *got[0].Content != "result text" {
		t.Errorf("content = %v", got[0].Content)
	}
}

func TestConvertMessage_ToolResultBeforeText(t *testing.T) {
	// A user turn carrying BOTH a tool_result and follow-up text must emit the
	// tool message FIRST (to stay adjacent to the preceding assistant
	// tool_calls), then the user text turn.
	m := &anthMessage{
		Role:    "user",
		Content: json.RawMessage(`[{"type":"tool_result","tool_use_id":"toolu_1","content":"42"},{"type":"text","text":"now do X"}]`),
	}
	got := convertMessage(m)
	if len(got) != 2 {
		t.Fatalf("got %d messages, want 2: %+v", len(got), got)
	}
	if got[0].Role != "tool" || got[0].ToolCallID != "toolu_1" {
		t.Errorf("msg[0] should be the tool result, got %+v", got[0])
	}
	if got[1].Role != "user" || got[1].Content == nil || *got[1].Content != "now do X" {
		t.Errorf("msg[1] should be the user text, got %+v", got[1])
	}
}

func TestConvertMessage_AssistantToolUse(t *testing.T) {
	m := &anthMessage{
		Role:    "assistant",
		Content: json.RawMessage(`[{"type":"text","text":"thinking about it"},{"type":"tool_use","id":"toolu_2","name":"Bash","input":{"cmd":"ls"}}]`),
	}
	got := convertMessage(m)
	if len(got) != 1 {
		t.Fatalf("got %d messages, want 1", len(got))
	}
	if got[0].Content == nil || *got[0].Content != "thinking about it" {
		t.Errorf("content = %v", got[0].Content)
	}
	if len(got[0].ToolCalls) != 1 || got[0].ToolCalls[0].Function.Arguments != `{"cmd":"ls"}` {
		t.Errorf("tool calls = %+v", got[0].ToolCalls)
	}
}

func TestConvertMessage_ToolResultWithListContent(t *testing.T) {
	m := &anthMessage{
		Role:    "user",
		Content: json.RawMessage(`[{"type":"tool_result","tool_use_id":"toolu_3","content":[{"type":"text","text":"line1"},{"type":"text","text":"line2"}]}]`),
	}
	got := convertMessage(m)
	if len(got) != 1 || got[0].Content == nil || *got[0].Content != "line1line2" {
		t.Fatalf("msg = %+v", got)
	}
}

func TestConvertTools_RenamesSchema(t *testing.T) {
	tools := []anthTool{{
		Name:        "Grep",
		Description: "search",
		InputSchema: json.RawMessage(`{"type":"object"}`),
	}}
	got := convertTools(tools)
	if len(got) != 1 {
		t.Fatalf("got %d tools", len(got))
	}
	if string(got[0].Parameters) != `{"type":"object"}` {
		t.Errorf("parameters = %s", got[0].Parameters)
	}
}

func TestConvertMessage_PlainString(t *testing.T) {
	m := &anthMessage{Role: "user", Content: json.RawMessage(`"hello there"`)}
	got := convertMessage(m)
	if len(got) != 1 || got[0].Content == nil || *got[0].Content != "hello there" {
		t.Fatalf("msg = %+v", got)
	}
}
