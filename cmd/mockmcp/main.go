// Command mockmcp is a fake upstream MCP server with two tools,
// payments.refund and notes.read, used to exercise the proxy. The notes are
// also served as resources, note://welcome and note://refund-policy.
//
// With -require-receipts it also plays the receiver's part: every tool call
// must carry a valid ConsequenceOS receipt, checked with one call to
// -verify-url, exactly as a real service would use pkg/verify. Its receiver
// API key is read from the env var named by -verify-key-env.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/matutozi/consequence-os/pkg/verify"
)

// version is set by release builds; see cmd/consequenced.
var version = "dev"

func main() {
	addr := flag.String("addr", "127.0.0.1:9090", "address to listen on")
	requireReceipts := flag.Bool("require-receipts", false, "refuse tool calls without a valid ConsequenceOS receipt")
	verifyURL := flag.String("verify-url", "http://127.0.0.1:8080", "ConsequenceOS server that checks receipts")
	keyEnv := flag.String("verify-key-env", "CONSEQUENCE_KEY_RECEIVER_PAYMENTS", "env var holding this receiver's API key")
	showVersion := flag.Bool("version", false, "print the version and exit")
	stdio := flag.Bool("stdio", false, "serve MCP on stdin and stdout, as a local server does, instead of HTTP")
	flag.Parse()
	if *showVersion {
		fmt.Println("mockmcp", version)
		return
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if *stdio {
		// stdout carries the protocol, so the log stays on stderr.
		if err := serveStdio(os.Stdin, os.Stdout, NewServer(defaultTools(), log)); err != nil {
			log.Error("stdio stopped", "err", err)
			os.Exit(1)
		}
		return
	}
	var handler http.Handler = NewServer(defaultTools(), log)
	if *requireReceipts {
		key := os.Getenv(*keyEnv)
		if key == "" {
			log.Error("-require-receipts needs this receiver's API key", "env", *keyEnv)
			os.Exit(1)
		}
		// This one line is all a receiver needs to refuse calls without proof.
		handler = verify.Middleware(verify.NewClient(*verifyURL, key), log)(handler)
		log.Info("receipts required", "verify_url", *verifyURL)
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", handler)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Info("mock MCP server listening", "url", "http://"+*addr+"/mcp")
	if err := srv.ListenAndServe(); err != nil {
		log.Error("server stopped", "err", err)
		os.Exit(1)
	}
}
