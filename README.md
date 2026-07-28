# SilkySwift

A minimal CONNECT-tunnel HTTPS intercepting proxy in Go. Captures
`api.anthropic.com/v1/*` HTTPS traffic and writes recordings to disk in
either raw HTTP wire format or a fine-tuning-ready `messages` format.
Stdlib only, zero external dependencies.

- CONNECT-tunnel HTTPS interception with per-SNI leaf certs minted by a
  locally generated CA.
- Raw HTTP wire-format recording of request / response pairs.
- Fine-tuning `messages` recording: reassembles the streamed (SSE)
  response into a single assistant turn and emits an OpenAI-style
  `messages` JSON per `/v1/messages` call — ready for Unsloth and any
  HuggingFace chat template.


## Install

For installation, you could use `brew`:

```
brew install sn3d/tap/silkyswift
```

You you can download binary for you system [here](https://github.com/sn3d/silkyswift/releases)


## Run

```bash
./silkyswift                                              # no recording, proxy only
./silkyswift --record ./recordings                        # record raw wire-format pairs
./silkyswift --record ./recordings --record-format both   # raw + fine-tuning samples
./silkyswift --listen 0.0.0.0:8080                        # bind all interfaces
```

On first run the proxy generates `ca.crt` and `ca.key` in the working
directory. On subsequent runs the existing pair is reused, so you only
need to install the CA into your trust store once.

## Recording formats

`--record DIR` enables recording; `--record-format` selects what is written
into that directory (default `raw`):

| Value      | Output per call                              | Use case                          |
| ---------- | -------------------------------------------- | --------------------------------- |
| `raw`      | `{prefix}_req.txt`, `{prefix}_resp.txt`      | Exact HTTP wire bytes; replay      |
| `messages` | `{prefix}_sample.json`                       | Fine-tuning (Unsloth / HF)         |
| `both`     | all of the above                             | Keep raw and export samples        |

`--record-format` has no effect without `--record`; passing `messages` or
`both` without a directory is an error.

The `messages` format captures the JSON payloads, not HTTP headers. Per
`/v1/messages` call it writes one self-contained conversation:

- The streamed SSE response is reassembled into a single assistant turn.
- `tool_use` blocks become OpenAI-style `tool_calls` (arguments as a JSON
  string); `tool_result` blocks become `role: "tool"` messages carrying the
  matching `tool_call_id`.
- The `system` field and each tool's schema (`input_schema` → `parameters`)
  are preserved; `thinking` blocks are kept as `reasoning_content`.
- Only `/v1/messages` yields samples; other `/v1/*` calls are raw-recorded
  only.

Each file is one training conversation, so load them directly, e.g. with
`datasets.load_dataset("json", data_files="recordings/*_sample.json")`.

Example line (abridged):

```json
{
  "id": "20260416-123432952_00016",
  "model": "claude-opus-4-6",
  "tools": [{ "name": "Grep", "parameters": { "type": "object" } }],
  "messages": [
    { "role": "system", "content": "You are Claude Code..." },
    { "role": "user", "content": "find the config" },
    { "role": "assistant", "content": "I'll search.",
      "tool_calls": [{ "id": "toolu_01", "type": "function",
        "function": { "name": "Grep", "arguments": "{\"pattern\":\"config\"}" } }] },
    { "role": "tool", "tool_call_id": "toolu_01", "content": "config.yaml" },
    { "role": "assistant", "content": "Found it in config.yaml." }
  ]
}
```

## Install the CA

**macOS:**

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ca.crt
```

**Linux (Debian/Ubuntu):**

```bash
sudo cp ca.crt /usr/local/share/ca-certificates/silkyswift.crt
sudo update-ca-certificates
```

**Simplest — no root, works for Claude Code:**

```bash
export NODE_EXTRA_CA_CERTS=$(pwd)/ca.crt
```

## Use

```bash
HTTPS_PROXY=http://127.0.0.1:8080 \
  NODE_EXTRA_CA_CERTS=$(pwd)/ca.crt \
  claude -p "say hi"
```

Only `api.anthropic.com/v1/*` is recorded; everything else is tunneled
transparently.

## Notes

- CA is reused across runs — install once into your trust store.
