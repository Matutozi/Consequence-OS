package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/matutozi/consequence-os/internal/policy"
	"github.com/matutozi/consequence-os/internal/toolpin"
)

// pinWait bounds how long the wrapper waits for the server to answer the
// tools/list it sends itself.
var pinWait = 10 * time.Second // a var so tests can shorten it

// pinListed is the stdio twin of the HTTP proxy's (pinlist.go): before a
// call to a tool not yet pinned is decided, the wrapper lists the server's
// tools itself, with the client's _meta, and pins them. The answer goes no
// further: the client never asked for it.
func (s *stdio) pinListed(ctx context.Context, name string, meta json.RawMessage) error {
	if s.opts.OpenTools == nil || policy.IsRead(name) {
		return nil
	}
	unpinned := func() bool {
		tools, closeTools, err := s.opts.OpenTools(ctx)
		if err != nil {
			return false // the gate reports it
		}
		defer closeTools()
		st, _, err := tools.Check(ctx, name, nil)
		return err == nil && st == toolpin.Unpinned
	}
	if !unpinned() {
		return nil
	}
	s.listMu.Lock()
	defer s.listMu.Unlock()
	if !unpinned() {
		return nil
	}
	cursor := ""
	for range maxListPages {
		line, err := s.askServer(ctx, meta, cursor)
		if err != nil {
			return fmt.Errorf("%w: %v", errListUnavailable, err)
		}
		tools, closeTools, err := s.opts.OpenTools(ctx)
		if err != nil {
			return fmt.Errorf("%w: %v", errListUnavailable, err)
		}
		_, err = filterListing(ctx, tools, toolpin.Lister{AgentID: s.opts.AgentID, OwnerID: s.opts.OwnerID}, line)
		closeTools()
		if err != nil {
			return fmt.Errorf("%w: %v", errListUnavailable, err)
		}
		var answer struct {
			Result *struct {
				NextCursor string `json:"nextCursor"`
			} `json:"result"`
		}
		if json.Unmarshal(line, &answer) != nil || answer.Result == nil {
			return fmt.Errorf("%w: the server answered the listing without a result", errListUnavailable)
		}
		if answer.Result.NextCursor == "" {
			return nil
		}
		cursor = answer.Result.NextCursor
	}
	return fmt.Errorf("%w: the listing runs to more than %d pages", errListUnavailable, maxListPages)
}

// askServer sends one tools/list to the server and waits for its answer,
// which relayFromServer hands over instead of passing it to the client.
func (s *stdio) askServer(ctx context.Context, meta json.RawMessage, cursor string) ([]byte, error) {
	params := map[string]any{}
	if len(meta) > 0 {
		params["_meta"] = meta
	}
	if cursor != "" {
		params["cursor"] = cursor
	}
	s.mu.Lock()
	s.pinSeq++
	id := fmt.Sprintf(`"consequenceos-pin-%d"`, s.pinSeq)
	answer := make(chan []byte, 1)
	s.pinWaits[id] = answer
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pinWaits, id)
		s.mu.Unlock()
	}()
	line, err := marshalRaw(map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(id), "method": methodToolsList, "params": params})
	if err != nil {
		return nil, err
	}
	if err := s.writeServer(line); err != nil {
		return nil, err
	}
	select {
	case got := <-answer:
		return got, nil
	case <-time.After(pinWait):
		return nil, fmt.Errorf("the server didn't answer within %s", pinWait)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// pinAnswer hands a line answering one of our own listings to the waiting
// pinListed, and reports whether it was one.
func (s *stdio) pinAnswer(id string, line []byte) bool {
	s.mu.Lock()
	answer, ok := s.pinWaits[id]
	s.mu.Unlock()
	if ok {
		answer <- append([]byte(nil), line...)
	}
	return ok
}
