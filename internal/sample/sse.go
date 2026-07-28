package sample

import (
	"bytes"
	"encoding/json"
	"strings"
)

// AssembledMessage is the reconstructed assistant turn: the streamed SSE
// deltas (or a single non-streamed JSON message) folded back into one message.
type AssembledMessage struct {
	Model      string
	StopReason string
	blocks     []assembledBlock
}

type assembledBlock struct {
	typ      string // "text" | "tool_use" | "thinking"
	text     strings.Builder
	toolID   string
	toolName string
	toolJSON strings.Builder // accumulated input_json_delta partials
}

// toMessage flattens the assembled blocks into a single OpenAI-style assistant
// message: text blocks concatenate into content, thinking blocks into
// reasoning_content, and tool_use blocks become tool_calls.
func (a *AssembledMessage) toMessage() Message {
	m := Message{Role: "assistant"}
	var texts, reasoning []string
	for i := range a.blocks {
		b := &a.blocks[i]
		switch b.typ {
		case "text":
			texts = append(texts, b.text.String())
		case "thinking":
			reasoning = append(reasoning, b.text.String())
		case "tool_use":
			args := strings.TrimSpace(b.toolJSON.String())
			if args == "" {
				args = "{}"
			}
			m.ToolCalls = append(m.ToolCalls, ToolCall{
				ID:       b.toolID,
				Type:     "function",
				Function: ToolFunction{Name: b.toolName, Arguments: args},
			})
		}
	}
	if len(texts) > 0 {
		m.Content = strPtr(strings.Join(texts, ""))
	}
	if len(reasoning) > 0 {
		m.ReasoningContent = strings.Join(reasoning, "")
	}
	return m
}

// Assembler folds an SSE byte stream into an AssembledMessage. It is fed chunk
// by chunk via Write (chunks may split mid-line) and finalized with Done. It is
// used by a single request goroutine and needs no locking.
type Assembler struct {
	buf       bytes.Buffer
	msg       AssembledMessage
	truncated bool
}

// NewAssembler returns an Assembler ready to receive SSE chunks.
func NewAssembler() *Assembler { return &Assembler{} }

// Write feeds a raw SSE chunk. Complete lines are parsed; a trailing partial
// line is retained until the next Write.
func (a *Assembler) Write(chunk []byte) {
	a.buf.Write(chunk)
	for {
		line, err := a.buf.ReadBytes('\n')
		if err != nil {
			// No full line yet: push the partial back for next Write.
			a.buf.Reset()
			a.buf.Write(line)
			return
		}
		a.consumeLine(line)
	}
}

func (a *Assembler) consumeLine(line []byte) {
	s := strings.TrimRight(string(line), "\r\n")
	// Truncation marker emitted by the proxy on a broken stream.
	if strings.HasPrefix(s, ": [silkyswift:") {
		a.truncated = true
		return
	}
	if !strings.HasPrefix(s, "data:") {
		return // event:, id:, comments, blank lines
	}
	payload := strings.TrimSpace(s[len("data:"):])
	if payload == "" || payload == "[DONE]" {
		return
	}
	a.handleEvent([]byte(payload))
}

// sseEvent covers every SSE data field we read.
type sseEvent struct {
	Type    string `json:"type"`
	Index   int    `json:"index"`
	Message struct {
		Model string `json:"model"`
	} `json:"message"`
	ContentBlock struct {
		Type string `json:"type"`
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"content_block"`
	Delta struct {
		Type        string `json:"type"`
		Text        string `json:"text"`
		Thinking    string `json:"thinking"`
		PartialJSON string `json:"partial_json"`
		StopReason  string `json:"stop_reason"`
	} `json:"delta"`
}

func (a *Assembler) handleEvent(payload []byte) {
	var e sseEvent
	if err := json.Unmarshal(payload, &e); err != nil {
		return
	}
	switch e.Type {
	case "message_start":
		a.msg.Model = e.Message.Model
	case "content_block_start":
		a.ensureBlock(e.Index)
		b := &a.msg.blocks[e.Index]
		b.typ = e.ContentBlock.Type
		b.toolID = e.ContentBlock.ID
		b.toolName = e.ContentBlock.Name
	case "content_block_delta":
		a.ensureBlock(e.Index)
		b := &a.msg.blocks[e.Index]
		switch e.Delta.Type {
		case "text_delta":
			b.text.WriteString(e.Delta.Text)
		case "thinking_delta":
			b.text.WriteString(e.Delta.Thinking)
		case "input_json_delta":
			b.toolJSON.WriteString(e.Delta.PartialJSON)
		}
	case "message_delta":
		if e.Delta.StopReason != "" {
			a.msg.StopReason = e.Delta.StopReason
		}
	}
}

// ensureBlock grows the block slice so index is addressable. SSE indices are
// contiguous from 0, but grow defensively.
func (a *Assembler) ensureBlock(index int) {
	for len(a.msg.blocks) <= index {
		a.msg.blocks = append(a.msg.blocks, assembledBlock{})
	}
}

// Truncate marks the stream as ended early (client disconnect or upstream
// read error), so the emitted sample records truncated:true with whatever
// content was assembled before the break.
func (a *Assembler) Truncate() { a.truncated = true }

// Done finalizes and returns the assembled message and whether the stream was
// truncated.
func (a *Assembler) Done() (*AssembledMessage, bool) {
	// Flush any buffered final line lacking a trailing newline.
	if a.buf.Len() > 0 {
		a.consumeLine(a.buf.Bytes())
		a.buf.Reset()
	}
	return &a.msg, a.truncated
}

// AssembleJSON reconstructs the assistant turn from a single non-streamed
// Messages API JSON response body.
func AssembleJSON(body []byte) (*AssembledMessage, bool) {
	var resp struct {
		Model      string      `json:"model"`
		StopReason string      `json:"stop_reason"`
		Content    []anthBlock `json:"content"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, false
	}
	m := &AssembledMessage{Model: resp.Model, StopReason: resp.StopReason}
	for i := range resp.Content {
		b := &resp.Content[i]
		ab := assembledBlock{typ: b.Type, toolID: b.ID, toolName: b.Name}
		switch b.Type {
		case "text":
			ab.text.WriteString(b.Text)
		case "thinking":
			ab.text.WriteString(b.Thinking)
		case "tool_use":
			ab.toolJSON.Write(b.Input)
		}
		m.blocks = append(m.blocks, ab)
	}
	return m, true
}
