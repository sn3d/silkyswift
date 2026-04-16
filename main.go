// silkyswift is a minimal CONNECT-tunnel HTTPS proxy in Go that writes raw
// HTTP wire-format recordings of api.anthropic.com /v1/* traffic to disk.
// Stdlib only, zero external dependencies.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/sn3d/silkyswift/internal/ca"
	"github.com/sn3d/silkyswift/internal/proxy"
	"github.com/sn3d/silkyswift/internal/recorder"
)

// version is set by goreleaser, via -ldflags="-X 'main.version=...'".
var version = "development"

func main() {
	var (
		listenAddr  = flag.String("listen", "127.0.0.1:8080", "proxy listen address")
		recordDir   = flag.String("record", "", "if set, record api.anthropic.com/v1/* pairs to DIR")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	authority, err := ca.LoadOrGenerate("ca.crt", "ca.key")
	if err != nil {
		fatal("CA", err)
	}

	caPath, err := filepath.Abs("ca.crt")
	if err != nil {
		caPath = "ca.crt"
	}

	var rec *recorder.Recorder
	if *recordDir != "" {
		rec, err = recorder.New(*recordDir)
		if err != nil {
			fatal("recorder", err)
		}
	}

	printBanner(caPath, *listenAddr, rec)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := proxy.Serve(ctx, *listenAddr, authority, rec); err != nil {
		fatal("proxy", err)
	}
}

// fatal prints a red error banner to stderr and exits 1. Color is disabled
// when stderr is not a TTY or NO_COLOR is set.
func fatal(stage string, err error) {
	const red = "\x1b[31m"
	const bold = "\x1b[1m"
	const reset = "\x1b[0m"
	useColor := os.Getenv("NO_COLOR") == "" && isTerminal(os.Stderr)
	if useColor {
		fmt.Fprintf(os.Stderr, "\n  %s%s✗ %s failed:%s %v\n\n", bold, red, stage, reset, err)
	} else {
		fmt.Fprintf(os.Stderr, "\n  ✗ %s failed: %v\n\n", stage, err)
	}
	os.Exit(1)
}

// ANSI styling. Enabled when stderr is a TTY and NO_COLOR is not set.
// Scope: bold + one accent (cyan) for headings/labels only. Commands stay plain.
type style struct {
	reset, bold, accent, dim string
}

func newStyle() style {
	if os.Getenv("NO_COLOR") != "" || !isTerminal(os.Stderr) {
		return style{}
	}
	return style{
		reset:  "\x1b[0m",
		bold:   "\x1b[1m",
		accent: "\x1b[36m", // cyan
		dim:    "\x1b[2m",
	}
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func printBanner(caPath, listenAddr string, rec *recorder.Recorder) {
	s := newStyle()
	w := os.Stderr

	fmt.Fprintf(w, "\n  %s%s🧵 SilkySwift%s %s— HTTPS proxy + recorder for Claude Code%s\n",
		s.bold, s.accent, s.reset, s.dim, s.reset)
	fmt.Fprintf(w, "  %s════════════════════════════════════════════════%s\n\n", s.dim, s.reset)

	fmt.Fprintf(w, "  %s🔌 Listening%s   http://%s\n", s.bold, s.reset, listenAddr)
	fmt.Fprintf(w, "  %s📜 CA cert%s     %s %s(reused across runs)%s\n",
		s.bold, s.reset, caPath, s.dim, s.reset)
	if rec != nil {
		fmt.Fprintf(w, "  %s🎙  Recording%s   %s %s(api.anthropic.com/v1/*)%s\n",
			s.bold, s.reset, rec.Dir(), s.dim, s.reset)
	} else {
		fmt.Fprintf(w, "  %s🎙  Recording%s   disabled %s(pass --record DIR to enable)%s\n",
			s.bold, s.reset, s.dim, s.reset)
	}
	fmt.Fprintln(w)

	printInstallSection(w, s, caPath)
	printRunSection(w, s, caPath, listenAddr)

	fmt.Fprintf(w, "  %s⌨  Ctrl-C to stop%s\n\n", s.dim, s.reset)
}

func sectionHeader(w *os.File, s style, icon, title string) {
	fmt.Fprintf(w, "  %s%s %s%s\n", s.bold, icon, title, s.reset)
}

func printInstallSection(w *os.File, s style, caPath string) {
	sectionHeader(w, s, "🔐", "Install CA")
	switch runtime.GOOS {
	case "darwin":
		fmt.Fprintf(w, "    sudo security add-trusted-cert -d -r trustRoot \\\n")
		fmt.Fprintf(w, "      -k /Library/Keychains/System.keychain %s\n\n", caPath)
	case "linux":
		fmt.Fprintf(w, "    sudo cp %s /usr/local/share/ca-certificates/silkyswift.crt\n", caPath)
		fmt.Fprintf(w, "    sudo update-ca-certificates\n\n")
	case "windows":
		fmt.Fprintf(w, "    certutil -addstore -f \"ROOT\" %s\n\n", caPath)
	default:
		fmt.Fprintf(w, "    Add %s to your OS trust store.\n\n", caPath)
	}

	fmt.Fprintf(w, "  %s💡 Or no-root (works for Claude Code)%s\n", s.dim, s.reset)
	fmt.Fprintf(w, "    export NODE_EXTRA_CA_CERTS=%s\n\n", caPath)
}

func printRunSection(w *os.File, s style, caPath, listenAddr string) {
	sectionHeader(w, s, "🚀", "Run Claude Code")
	fmt.Fprintf(w, "    HTTPS_PROXY=http://%s \\\n", listenAddr)
	fmt.Fprintf(w, "    NODE_EXTRA_CA_CERTS=%s \\\n", caPath)
	fmt.Fprintf(w, "      claude\n\n")
}
