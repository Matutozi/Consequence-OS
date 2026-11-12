package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/matutozi/consequence-os/internal/config"
	"github.com/matutozi/consequence-os/internal/gate"
)

// Every answer from the upstream is read on its way to the agent: tool
// listings are checked against the pins (listing.go), and requests the
// server makes of the client go past the policy (serverreq.go). A JSON
// answer is read whole; an SSE stream is read an event at a time, so
// events still arrive as they come. An answer that can't be read isn't
// passed on.

// forwarded is a request on its way to the upstream: who sent it, and what
// it was, for checking the answer.
type forwarded struct {
	agent  config.Agent
	method string // empty for a GET stream
	id     json.RawMessage
}

// forwardedKey is the context key for the forwarded request.
type forwardedKey struct{}

// errUnchecked means an answer couldn't be checked, so it didn't reach
// the agent.
var errUnchecked = errors.New("the server's answer couldn't be checked, so it wasn't passed on")

// checkResponse is the reverse proxy's ModifyResponse step.
func (p *Proxy) checkResponse(resp *http.Response) error {
	if p.upstreamToken != "" {
		redactHeaders(resp.Header, p.upstreamToken)
		resp.Body = newRedactor(resp.Body, p.upstreamToken)
	}
	// After the redactor, so the token can't end up in a pin or the audit log.
	ctx := resp.Request.Context()
	fw, ok := ctx.Value(forwardedKey{}).(forwarded)
	if !ok || resp.StatusCode != http.StatusOK {
		return nil // nothing of ours, or an HTTP error, which carries no MCP messages
	}
	l, isListing := ctx.Value(listingKey{}).(listing)
	isListing = isListing && p.tools != nil
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if mediaType != "application/json" && mediaType != "text/event-stream" {
		if isListing {
			return fmt.Errorf("%w: its content type %q is neither JSON nor an event stream", errUncheckedListing, mediaType)
		}
		return nil // no MCP message in it
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" && enc != "identity" {
		return fmt.Errorf("%w: it came compressed (%s), though ConsequenceOS didn't ask for that", errUnchecked, enc)
	}

	check := p.serverCheck(fw.agent)
	methodOf := func(json.RawMessage) string { return fw.method }
	filter := func(msg []byte) ([]byte, bool, error) {
		if isListing {
			var err error
			if msg, err = filterListing(ctx, p.tools, l.by, msg); err != nil {
				return nil, false, err
			}
		}
		out, keep, answer := check.message(ctx, msg, methodOf)
		if answer != nil {
			p.answerServer(resp.Request, answer)
		}
		return out, keep, nil
	}

	if mediaType == "text/event-stream" {
		resp.Body = &sseFilter{src: resp.Body, br: bufio.NewReader(resp.Body), filter: func(data []byte) ([]byte, bool, error) {
			out, keep, err := filter(data)
			if err != nil {
				// The stream stops here, so nothing unchecked follows.
				p.log.Error("answer not passed on; the event stream was cut off", "err", err)
			}
			return out, keep, err
		}}
		resp.ContentLength = -1
		resp.Header.Del("Content-Length")
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCheckedBytes+1))
	_ = resp.Body.Close()
	if err != nil {
		return err
	}
	if len(body) > maxCheckedBytes {
		return fmt.Errorf("%w: it is over %d bytes", errUnchecked, maxCheckedBytes)
	}
	out, keep, err := filter(body)
	if err != nil {
		return err
	}
	if !keep {
		// The answer to the agent's request was itself a request: refused,
		// and the agent gets an error in its place.
		out, _ = marshalRaw(errorResponse(fw.id, codeInternalError, "the server answered with a request that ConsequenceOS refused"))
	}
	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
	return nil
}

// serverCheck checks the server's requests for agent, with the proxy's gate.
func (p *Proxy) serverCheck(agent config.Agent) serverCheck {
	return serverCheck{
		open:    func(context.Context) (*gate.Gate, func(), error) { return p.gate, func() {}, nil },
		agentID: agent.ID, ownerID: agent.OwnerID, log: p.log,
	}
}

// answerServer sends the upstream the answer to a request of its that was
// refused, as the client would have, so the server doesn't wait for it:
// a POST in the same session, with the upstream's token if there is one.
// It runs in the background; a failure is only logged.
func (p *Proxy) answerServer(out *http.Request, answer []byte) {
	url := out.URL.String()
	header := http.Header{}
	// out is the request as sent upstream: the agent's own key is gone,
	// and Authorization is the upstream's token, if any.
	for _, h := range []string{"Mcp-Session-Id", headerProtocolVersion, "Authorization"} {
		if v := out.Header.Get(h); v != "" {
			header.Set(h, v)
		}
	}
	header.Set("Content-Type", "application/json")
	header.Set("Accept", "application/json, text/event-stream")
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(answer))
		if err != nil {
			p.log.Error("answer the server's refused request", "err", err)
			return
		}
		req.Header = header
		resp, err := p.client.Do(req)
		if err != nil {
			p.log.Error("answer the server's refused request", "err", err)
			return
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if resp.StatusCode >= 300 {
			p.log.Warn("the server didn't take the answer to its refused request", "status", resp.StatusCode)
		}
	}()
}
