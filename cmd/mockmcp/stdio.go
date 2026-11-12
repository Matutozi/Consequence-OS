package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
)

// serveStdio serves MCP over stdin and stdout, one message per line, the
// way local MCP servers do. Each line goes through the HTTP handler, with
// the headers a Streamable HTTP client would send, so both transports
// share one implementation.
func serveStdio(in io.Reader, out io.Writer, h http.Handler) error {
	br := bufio.NewReader(in)
	for {
		line, err := br.ReadBytes('\n')
		if line = bytes.TrimSpace(line); len(line) > 0 {
			req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(line))
			setHeaders(req, line)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if body := bytes.TrimSpace(rec.Body.Bytes()); len(body) > 0 && rec.Code != http.StatusAccepted {
				if _, werr := out.Write(append(body, '\n')); werr != nil {
					return werr
				}
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// setHeaders adds what a 2026-07-28 client puts in headers, taken from the
// message itself: there are no headers on stdio.
func setHeaders(req *http.Request, line []byte) {
	req.Header.Set("Content-Type", "application/json")
	var m struct {
		Method string `json:"method"`
		Params struct {
			Name string                     `json:"name"`
			URI  string                     `json:"uri"`
			Meta map[string]json.RawMessage `json:"_meta"`
		} `json:"params"`
	}
	if json.Unmarshal(line, &m) != nil {
		return
	}
	req.Header.Set(headerMethod, m.Method)
	var version string
	if json.Unmarshal(m.Params.Meta[metaProtocolVersion], &version) == nil && version != "" {
		req.Header.Set(headerProtocolVersion, version)
	}
	switch {
	case m.Params.URI != "":
		req.Header.Set(headerName, m.Params.URI)
	case m.Params.Name != "":
		req.Header.Set(headerName, m.Params.Name)
	}
}
