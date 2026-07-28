// Package sample records intercepted Anthropic Messages API calls as
// fine-tuning samples in the OpenAI-style "messages" format that Unsloth (and
// any HuggingFace chat template) ingests. Unlike the raw wire recorder it
// discards HTTP headers and reassembles the streamed (SSE) response into a
// single assistant turn, preserving tool_use / tool_result blocks as
// tool_calls and role:"tool" messages.
//
// One {prefix}_sample.json file is written per request/response pair, sharing
// the recorder prefix scheme so raw .txt and .json recordings sit side by side.
package sample

import "encoding/json"

// Sample is the top-level record written to {prefix}_sample.json.
type Sample struct {
	ID       string    `json:"id"`
	TS       string    `json:"ts"`
	Model    string    `json:"model"`
	Tools    []Tool    `json:"tools,omitempty"`
	Messages []Message `json:"messages"`
	// Truncated is set when the response stream ended early (client
	// disconnect or upstream error) so partial samples are self-describing.
	Truncated bool `json:"truncated,omitempty"`
}

// Tool is an available tool in OpenAI/template convention: the Anthropic
// input_schema field is renamed to parameters so apply_chat_template(tools=...)
// consumes it directly.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

// Message is one conversation turn. Content is a *string (nil for an
// assistant turn that only carries tool_calls) so we can emit JSON null.
type Message struct {
	Role    string  `json:"role"`
	Content *string `json:"content"`
	// ReasoningContent holds concatenated thinking-block text on an assistant
	// turn when present. Downstream trainers may ignore it.
	ReasoningContent string `json:"reasoning_content,omitempty"`
	// ToolCalls is set on an assistant turn that invoked tools.
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
	// ToolCallID links a role:"tool" message to the assistant tool_call it answers.
	ToolCallID string `json:"tool_call_id,omitempty"`
}

// ToolCall is an assistant-invoked tool in OpenAI convention. Function
// arguments are a JSON *string*, not an object.
type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"` // always "function"
	Function ToolFunction `json:"function"`
}

// ToolFunction carries the tool name and its arguments as a JSON string.
type ToolFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// --- Anthropic request wire shapes (only the fields we consume) ---

// anthReq is the parsed request body. system may be a string or a list of
// text blocks, so it is decoded lazily via json.RawMessage.
type anthReq struct {
	Model    string          `json:"model"`
	System   json.RawMessage `json:"system"`
	Messages []anthMessage   `json:"messages"`
	Tools    []anthTool      `json:"tools"`
}

type anthTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// anthMessage.Content may be a plain string or a list of content blocks, so it
// is captured raw and decoded by contentBlocks.
type anthMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

// anthBlock covers every content-block variant we read from request messages
// and the assembled response: text, tool_use, tool_result, thinking.
type anthBlock struct {
	Type string `json:"type"`
	// text
	Text string `json:"text"`
	// thinking
	Thinking string `json:"thinking"`
	// tool_use
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
	// tool_result
	ToolUseID string          `json:"tool_use_id"`
	Content   json.RawMessage `json:"content"`
}
