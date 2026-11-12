package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"

	"github.com/matutozi/consequence-os/internal/toolpin"
	"github.com/matutozi/consequence-os/pkg/verify"
)

// Tool listings are read on their way to the agent, so toolpin can pin
// each tool's definition and leave out the ones that changed. Both
// adapters pass every message of a tools/list answer through
// filterListing; this file also reads the HTTP answer, which is one JSON
// message or an SSE stream of them.

const methodToolsList = "tools/list"

// maxListingBytes bounds a tools/list answer, or one SSE event of it,
// that we read whole. Listings with many tools and long schemas run
// larger than calls.
const maxListingBytes = 16 << 20 // 16 MiB

// listing is a tools/list request on its way to the upstream: its ID, for
// an error answer, and who asked.
type listing struct {
	id json.RawMessage
	by toolpin.Lister
}

// listingKey is the context key for the listing a forwarded request is.
type listingKey struct{}

// errUncheckedListing means a listing couldn't be checked, so it didn't
// reach the agent.
var errUncheckedListing = errors.New("the tool list couldn't be checked against the pinned tool definitions, so it wasn't passed on")

// filterListing returns msg with its tools filtered, when it is a
// response with a result. The caller has made sure that any response msg
// may be answers the tools/list. On an error, the message must not reach
// the agent.
//
// Answers aren't matched to the request by ID here: a server could answer
// with 1.0 for 1, which a client may take as the same ID. Over HTTP every
// response in the answer to a request is that request's; the stdio wrapper
// compares IDs in canonical form (listingID).
func filterListing(ctx context.Context, tools *toolpin.Service, by toolpin.Lister, msg []byte) ([]byte, error) {
	if len(bytes.TrimSpace(msg)) == 0 {
		return msg, nil // an SSE event with no data, such as one that primes reconnection
	}
	// Anything else must be JSON our parser and the agent's read the same:
	// none of the NaN some parsers accept, so it can't pass here as "not
	// a listing" yet list tools there; no duplicate keys, of which parsers
	// keep different copies; no invalid UTF-8, which Go would quietly
	// replace. Keys that differ only in letter case are fine: a schema may
	// name both id and ID.
	if _, err := verify.Canonicalize(msg); err != nil {
		return nil, fmt.Errorf("%w: %v", errUncheckedListing, err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(msg, &top); err != nil {
		return nil, fmt.Errorf("%w: it isn't a JSON-RPC message", errUncheckedListing)
	}
	if _, isRequest := top["method"]; isRequest {
		return msg, nil
	}
	result, ok := top["result"]
	if !ok {
		return msg, nil // an error answer lists no tools
	}
	filtered, err := tools.ObserveList(ctx, by, result)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errUncheckedListing, err)
	}
	if bytes.Equal(filtered, result) {
		return msg, nil
	}
	top["result"] = filtered
	return marshalRaw(top)
}

// listingID is a JSON-RPC ID in canonical form, so 1, 1.0 and 1e0 are one
// ID, as they are to a JavaScript client. ok is false for no ID.
func listingID(id json.RawMessage) (string, bool) {
	if len(id) == 0 || string(id) == "null" {
		return "", false
	}
	c, err := verify.Canonicalize(id)
	if err != nil {
		return "", false
	}
	return string(c), true
}

// checkListingResponse is the reverse proxy's ModifyResponse step for a
// forwarded tools/list. A JSON answer is read whole and filtered; an SSE
// stream is filtered an event at a time, so other events still arrive
// as they come. Anything we can't read fails: the listing never reaches
// the agent unchecked.
func checkListingResponse(resp *http.Response, tools *toolpin.Service, l listing, log *slog.Logger) error {
	if resp.StatusCode != http.StatusOK {
		return nil // no result to list tools in
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" && enc != "identity" {
		return fmt.Errorf("%w: it came compressed (%s)", errUncheckedListing, enc)
	}
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	ctx := resp.Request.Context()
	switch mediaType {
	case "application/json":
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxListingBytes+1))
		_ = resp.Body.Close()
		if err != nil {
			return err
		}
		if len(body) > maxListingBytes {
			return fmt.Errorf("%w: it is over %d bytes", errUncheckedListing, maxListingBytes)
		}
		out, err := filterListing(ctx, tools, l.by, body)
		if err != nil {
			return err
		}
		resp.Body = io.NopCloser(bytes.NewReader(out))
		resp.ContentLength = int64(len(out))
		resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
		return nil
	case "text/event-stream":
		resp.Body = &sseFilter{src: resp.Body, br: bufio.NewReader(resp.Body), filter: func(data []byte) ([]byte, error) {
			out, err := filterListing(ctx, tools, l.by, data)
			if err != nil {
				// The stream stops here, so the agent never gets the listing.
				log.Error("tool list not passed on; the event stream was cut off", "err", err)
			}
			return out, err
		}}
		resp.ContentLength = -1
		resp.Header.Del("Content-Length")
		return nil
	default:
		return fmt.Errorf("%w: its content type %q is neither JSON nor an event stream", errUncheckedListing, mediaType)
	}
}

// sseFilter passes an SSE stream through an event at a time, rewriting
// the data of each event with filter. An event's lines other than data
// (id, event, retry, comments) are kept, in order; its data goes where the
// first data line was, a data line for each line of it.
type sseFilter struct {
	src    io.ReadCloser
	br     *bufio.Reader
	filter func(data []byte) ([]byte, error)
	out    bytes.Buffer // filtered bytes not yet read
	err    error        // returned once out is drained
}

func (f *sseFilter) Read(p []byte) (int, error) {
	for f.out.Len() == 0 && f.err == nil {
		f.err = f.nextEvent()
	}
	if f.out.Len() > 0 {
		return f.out.Read(p)
	}
	return 0, f.err
}

func (f *sseFilter) Close() error { return f.src.Close() }

// nextEvent reads one event, through the blank line that ends it, and
// writes it filtered to f.out. Lines may end in LF, CRLF or a lone CR,
// as the SSE spec allows; they are written back ending in LF.
func (f *sseFilter) nextEvent() error {
	var lines [][]byte
	var data [][]byte
	firstData := -1
	size := 0
	for {
		line, err := readSSELine(f.br, maxListingBytes-size)
		if err != nil {
			if errors.Is(err, io.EOF) && len(line) == 0 && len(lines) == 0 {
				return io.EOF
			}
			if errors.Is(err, io.EOF) {
				break // the stream ended mid-event: pass on what there is
			}
			return err
		}
		size += len(line) + 1
		if len(line) == 0 {
			break // the end of the event
		}
		if field, value, ok := bytes.Cut(line, []byte(":")); ok && string(field) == "data" {
			if firstData < 0 {
				firstData = len(lines)
				lines = append(lines, nil) // where the data goes
			}
			data = append(data, bytes.TrimPrefix(value, []byte(" ")))
			continue
		}
		if string(line) == "data" { // a data line with no colon has empty data
			if firstData < 0 {
				firstData = len(lines)
				lines = append(lines, nil)
			}
			data = append(data, nil)
			continue
		}
		lines = append(lines, line)
	}
	if firstData >= 0 {
		filtered, err := f.filter(bytes.Join(data, []byte("\n")))
		if err != nil {
			return err
		}
		var d bytes.Buffer
		for i, part := range bytes.Split(filtered, []byte("\n")) {
			if i > 0 {
				d.WriteByte('\n')
			}
			d.WriteString("data: ")
			d.Write(part)
		}
		lines[firstData] = d.Bytes()
	}
	for _, line := range lines {
		f.out.Write(line)
		f.out.WriteByte('\n')
	}
	f.out.WriteByte('\n')
	return nil
}

// readSSELine reads one line without its ending. Past max bytes it fails:
// the event can't be checked.
func readSSELine(br *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	for {
		b, err := br.ReadByte()
		if err != nil {
			return line, err
		}
		switch b {
		case '\n':
			return line, nil
		case '\r':
			if next, err := br.Peek(1); err == nil && next[0] == '\n' {
				_, _ = br.ReadByte()
			}
			return line, nil
		}
		if len(line) >= max {
			return nil, fmt.Errorf("%w: an event is over %d bytes", errUncheckedListing, maxListingBytes)
		}
		line = append(line, b)
	}
}
