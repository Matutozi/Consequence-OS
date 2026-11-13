package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/matutozi/consequence-os/internal/policy"
	"github.com/matutozi/consequence-os/internal/toolpin"
)

// A call is checked against its tool's pinned definition: arguments the
// accepted schema doesn't name are refused. Tools are pinned when the
// upstream lists them, which every MCP client asks for before calling.
// An agent that calls a tool without listing first (no client does, but a
// hostile one may) would find nothing pinned, so the gate refuses a call
// to an unpinned tool. To keep that from refusing honest calls on a fresh
// gate, the proxy lists the upstream's tools itself first, as the agent
// would have: pinListed below. What is still unpinned after that is a
// tool the server doesn't list.

// listAs is how the agent speaks to the upstream, so the proxy's listing
// speaks the same: the protocol revision in its _meta, and the HTTP
// headers of its session.
type listAs struct {
	meta   json.RawMessage // the agent's _meta, or nil for a client from before 2026-07-28
	header http.Header
}

// maxListPages bounds how many pages of a paginated listing are read.
const maxListPages = 50

// errListUnavailable means the upstream's tool list couldn't be read, so
// a call to a tool not yet pinned can't be checked.
var errListUnavailable = errors.New("the tool server's tool list couldn't be read to check this call, so it wasn't forwarded")

// pinListed makes sure a call to a tool is decided against the upstream's
// listing: if the tool isn't pinned yet, the upstream's tools are listed
// and pinned first. Reads, and the server's requests, aren't tools.
func (p *Proxy) pinListed(ctx context.Context, name string, by toolpin.Lister, as listAs) error {
	if p.tools == nil || policy.IsRead(name) {
		return nil
	}
	if st, _, err := p.tools.Check(ctx, name, nil); err != nil || st != toolpin.Unpinned {
		return nil // a lookup error is the gate's to report
	}
	p.listMu.Lock() // one listing at a time: a burst of first calls lists once
	defer p.listMu.Unlock()
	if st, _, err := p.tools.Check(ctx, name, nil); err != nil || st != toolpin.Unpinned {
		return nil // listed meanwhile
	}
	if err := p.listUpstream(ctx, by, as); err != nil {
		return fmt.Errorf("%w: %v", errListUnavailable, err)
	}
	return nil
}

// listUpstream lists the upstream's tools, every page, through the same
// check an agent's listing takes, which pins them.
func (p *Proxy) listUpstream(ctx context.Context, by toolpin.Lister, as listAs) error {
	cursor := ""
	for page := range maxListPages {
		id := fmt.Sprintf("consequenceos-pin-%d", page)
		params := map[string]any{}
		if len(as.meta) > 0 {
			params["_meta"] = as.meta
		}
		if cursor != "" {
			params["cursor"] = cursor
		}
		body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": methodToolsList, "params": params})
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.upstream.String(), bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set(headerMethod, methodToolsList)
		for _, h := range []string{headerProtocolVersion, "Mcp-Session-Id"} {
			if v := as.header.Get(h); v != "" {
				req.Header.Set(h, v)
			}
		}
		if p.upstreamToken != "" {
			req.Header.Set("Authorization", "Bearer "+p.upstreamToken)
		}
		resp, err := p.client.Do(req)
		if err != nil {
			return err
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxCheckedBytes+1))
		resp.Body.Close()
		switch {
		case err != nil:
			return err
		case len(data) > maxCheckedBytes:
			return fmt.Errorf("the listing is over %d bytes", maxCheckedBytes)
		case resp.StatusCode != http.StatusOK:
			return fmt.Errorf("the server answered HTTP %d", resp.StatusCode)
		}
		msg := data
		if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
			if msg = sseAnswer(data, id); msg == nil {
				return errors.New("the server's event stream held no answer to the listing")
			}
		}
		if _, err := filterListing(ctx, p.tools, by, msg); err != nil {
			return err
		}
		var answer struct {
			Result *struct {
				NextCursor string `json:"nextCursor"`
			} `json:"result"`
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(msg, &answer); err != nil || answer.Result == nil {
			why := "no result"
			if answer.Error != nil {
				why = answer.Error.Message
			}
			return fmt.Errorf("the server answered the listing with %s", why)
		}
		if answer.Result.NextCursor == "" {
			return nil
		}
		cursor = answer.Result.NextCursor
	}
	return fmt.Errorf("the listing runs to more than %d pages", maxListPages)
}

// sseAnswer finds, in an SSE body, the data of the event that answers
// the request with this ID, or nil.
func sseAnswer(body []byte, id string) []byte {
	want, _ := json.Marshal(id)
	for _, event := range bytes.Split(bytes.ReplaceAll(body, []byte("\r\n"), []byte("\n")), []byte("\n\n")) {
		var data [][]byte
		for _, line := range bytes.Split(event, []byte("\n")) {
			if v, ok := bytes.CutPrefix(line, []byte("data:")); ok {
				data = append(data, bytes.TrimPrefix(v, []byte(" ")))
			}
		}
		msg := bytes.Join(data, []byte("\n"))
		var m struct {
			ID json.RawMessage `json:"id"`
		}
		if json.Unmarshal(msg, &m) == nil && bytes.Equal(m.ID, want) {
			return msg
		}
	}
	return nil
}
