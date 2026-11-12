package main

import (
	"io"
	"log/slog"
	"strings"
	"testing"
)

func TestServeStdio(t *testing.T) {
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`, // no answer
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"notes.read","arguments":{"note_id":"welcome"},` +
			`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"note://welcome",` +
			`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`,
	}, "\n") + "\n"
	var out strings.Builder
	if err := serveStdio(strings.NewReader(in), &out, NewServer(defaultTools(), slog.New(slog.NewTextHandler(io.Discard, nil)))); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], `"id":1`) || !strings.Contains(lines[1], `"id":2`) || !strings.Contains(lines[2], "Welcome to the mock notes store") {
		t.Errorf("got:\n%s", out.String())
	}
	if strings.Contains(out.String(), "Header mismatch") {
		t.Errorf("the headers taken from each message don't match it:\n%s", out.String())
	}
}
