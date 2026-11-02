// Command mockmcp is a fake upstream MCP server with two tools,
// payments.refund and notes.read, used to exercise the proxy.
//
// With -require-receipts it also plays the receiver's part: every tool call
// must carry a valid ConsequenceOS receipt, checked with one call to
// -verify-url, exactly as a real service would use pkg/verify.
package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/matutozi/consequence-os/pkg/verify"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9090", "address to listen on")
	requireReceipts := flag.Bool("require-receipts", false, "refuse tool calls without a valid ConsequenceOS receipt")
	verifyURL := flag.String("verify-url", "http://127.0.0.1:8080", "ConsequenceOS server that checks receipts")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	var handler http.Handler = NewServer(defaultTools(), log)
	if *requireReceipts {
		// This one line is all a receiver needs to refuse calls without proof.
		handler = verify.Middleware(verify.NewClient(*verifyURL), log)(handler)
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
