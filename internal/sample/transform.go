package sample

import (
	"encoding/json"
	"strings"
)

// buildMessages maps a parsed Anthropic request plus the assembled response
// message into the OpenAI-style messages list. The request already carries the
// full running conversation; the assembled assistant turn is appended as the
// final message.
func buildMessages(req *anthReq, assembled *AssembledMessage) []Message {
	var out []Message

	if sys := systemText(req.System); sys != "" {
		out = append(out, Message{Role: "system", Content: strPtr(sys)})
	}

	for i := range req.Messages {
		out = append(out, convertMessage(&req.Messages[i])...)
	}

	if assembled != nil {
		out = append(out, assembled.toMessage())
	}

	return out
}

// convertMessage expands one request message into one or more output messages.
// A single Anthropic message can yield an assistant turn plus (for a user
// message carrying tool_result blocks) several role:"tool" messages.
func convertMessage(m *anthMessage) []Message {
	blocks, ok := contentBlocks(m.Content)
	if !ok {
		// Plain-string content: emit verbatim.
		var s string
		_ = json.Unmarshal(m.Content, &s)
		return []Message{{Role: m.Role, Content: strPtr(s)}}
	}

	var (
		texts     []string
		reasoning []string
		toolCalls []ToolCall
		toolMsgs  []Message
	)
	for i := range blocks {
		b := &blocks[i]
		switch b.Type {
		case "text":
			texts = append(texts, b.Text)
		case "thinking":
			reasoning = append(reasoning, b.Thinking)
		case "tool_use":
			toolCalls = append(toolCalls, toolCallFromBlock(b))
		case "tool_result":
			toolMsgs = append(toolMsgs, Message{
				Role:       "tool",
				ToolCallID: b.ToolUseID,
				Content:    strPtr(toolResultText(b.Content)),
			})
		}
	}

	// Emit tool_result messages FIRST. They answer the preceding assistant's
	// tool_calls, and the OpenAI/HuggingFace chat format requires each
	// role:"tool" message to immediately follow that assistant turn — a user
	// text turn interposed between them breaks the adjacency and reorders the
	// tool responses. Any accompanying user text is a follow-up instruction
	// and correctly comes after the tool results.
	msgs := make([]Message, 0, len(toolMsgs)+1)
	msgs = append(msgs, toolMsgs...)

	// A pure tool_result carrier (no text, no tool_calls) yields only the tool
	// messages — no redundant empty turn.
	if len(texts) == 0 && len(reasoning) == 0 && len(toolCalls) == 0 {
		return msgs
	}

	primary := Message{Role: m.Role}
	if len(texts) > 0 {
		primary.Content = strPtr(strings.Join(texts, ""))
	}
	if len(reasoning) > 0 {
		primary.ReasoningContent = strings.Join(reasoning, "")
	}
	if len(toolCalls) > 0 {
		primary.ToolCalls = toolCalls
	}
	return append(msgs, primary)
}

func toolCallFromBlock(b *anthBlock) ToolCall {
	args := string(b.Input)
	if args == "" || args == "null" {
		args = "{}"
	}
	return ToolCall{
		ID:   b.ID,
		Type: "function",
		Function: ToolFunction{
			Name:      b.Name,
			Arguments: args,
		},
	}
}

// convertTools renames input_schema -> parameters for template consumption.
func convertTools(tools []anthTool) []Tool {
	if len(tools) == 0 {
		return nil
	}
	out := make([]Tool, 0, len(tools))
	for i := range tools {
		out = append(out, Tool{
			Name:        tools[i].Name,
			Description: tools[i].Description,
			Parameters:  tools[i].InputSchema,
		})
	}
	return out
}

// systemText flattens the Anthropic system field, which is either a JSON
// string or a list of text blocks, into a single string.
func systemText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	blocks, ok := contentBlocks(raw)
	if !ok {
		return ""
	}
	var parts []string
	for i := range blocks {
		if blocks[i].Type == "text" {
			parts = append(parts, blocks[i].Text)
		}
	}
	return strings.Join(parts, "\n")
}

// toolResultText flattens a tool_result content field (string or list of text
// blocks) into a single string.
func toolResultText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	blocks, ok := contentBlocks(raw)
	if !ok {
		return string(raw)
	}
	var parts []string
	for i := range blocks {
		if blocks[i].Type == "text" {
			parts = append(parts, blocks[i].Text)
		}
	}
	return strings.Join(parts, "")
}

// contentBlocks decodes a content field as a list of blocks, reporting false
// if it is not a JSON array.
func contentBlocks(raw json.RawMessage) ([]anthBlock, bool) {
	trimmed := strings.TrimLeft(string(raw), " \t\r\n")
	if !strings.HasPrefix(trimmed, "[") {
		return nil, false
	}
	var blocks []anthBlock
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return nil, false
	}
	return blocks, true
}

func strPtr(s string) *string { return &s }
