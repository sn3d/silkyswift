# SilkySwift

A minimal CONNECT-tunnel HTTPS intercepting proxy in Go. Captures
`api.anthropic.com/v1/*` HTTPS traffic and writes raw HTTP wire-format
recordings to disk. Stdlib only, zero external dependencies.

- CONNECT-tunnel HTTPS interception with per-SNI leaf certs minted by a
  locally generated CA.
- Raw HTTP wire-format recording of request / response pairs.


## Install

Download the latest binary from
[Releases](https://github.com/sn3d/silkyswift/releases/latest), or build
from source:

```bash
git clone https://github.com/sn3d/silkyswift.git
cd silkyswift
go build -o silkyswift .
```

## Run

```bash
./silkyswift                          # no recording, proxy only
./silkyswift --record ./recordings    # record api.anthropic.com/v1/* pairs
./silkyswift --listen 0.0.0.0:8080    # bind all interfaces
```

On first run the proxy generates `ca.crt` and `ca.key` in the working
directory. On subsequent runs the existing pair is reused, so you only
need to install the CA into your trust store once.

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
