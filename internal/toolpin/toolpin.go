// Package toolpin pins what each tool of an upstream MCP server says it
// does, so a server can't change a tool under its old name.
//
// Policy goes by tool name: levels, rules and approvals all name the tool.
// A server that changes what notes.read does, or adds a delete_all argument
// to it, keeps the old name, the old level and the old rules. That is the
// MCP "rug pull". So the adapters show this package every tools/list result
// on its way to the agent:
//
//   - A tool seen for the first time is pinned: the hash of its definition
//     is kept, with the definition itself (trust on first use).
//   - A tool whose definition differs from its pin is changed. It is left
//     out of the listing, so its new description never reaches the model,
//     and its calls ask until a person accepts the change with
//     consequenced -accept-tool. Deny rules still deny it.
//   - A call to a pinned tool with an argument its accepted input schema
//     doesn't name is refused. See unnamed.go.
//
// Each pin, change and acceptance is written to the audit log.
package toolpin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/pkg/verify"
)

// RuleChanged is the rule name a call to a changed tool is decided by.
const RuleChanged = "tool-changed"

// pinnedFields are the parts of a definition that are pinned: what the
// model reads to decide what a tool does, and what it may send it. Other
// fields, such as icons, outputSchema and _meta, may change freely.
var pinnedFields = []string{"name", "title", "description", "inputSchema", "annotations"}

// Pin is what the store keeps about one tool of one server.
type Pin struct {
	// Server names the upstream: its URL, or the command of a stdio server.
	Server string `json:"server"`
	Tool   string `json:"tool"`
	// Hash is "sha256:<hex>" of the accepted definition's canonical JSON.
	Hash       string          `json:"hash"`
	Definition json.RawMessage `json:"definition"`
	PinnedAt   time.Time       `json:"pinned_at"`
	// AcceptedBy names who accepted the definition, or is empty when it
	// was pinned the first time the tool was seen.
	AcceptedBy string `json:"accepted_by,omitempty"`
	// Seen is the hash of a different definition the server has listed
	// since, not yet accepted; empty when the last listing matched the pin.
	Seen           string          `json:"seen,omitempty"`
	SeenDefinition json.RawMessage `json:"seen_definition,omitempty"`
	SeenAt         time.Time       `json:"seen_at,omitzero"`
}

// Changed reports whether the server last listed a definition other than
// the accepted one.
func (p Pin) Changed() bool { return p.Seen != "" }

// Repository is the part of the store that keeps pins.
type Repository interface {
	// ToolPin returns the pin of server's tool, or ok=false when there is none.
	ToolPin(ctx context.Context, server, tool string) (p Pin, ok bool, err error)
	// ListToolPins returns server's pins, or every server's when server
	// is empty, sorted by server and then tool.
	ListToolPins(ctx context.Context, server string) ([]Pin, error)
	// UpdateToolPin calls update with server's pin of tool (ok=false when
	// there is none) and saves what it returns when save is true, all in
	// one step: no other change to that pin can come in between. update
	// must not block or call the store. It returns the pin as it stands
	// afterwards.
	UpdateToolPin(ctx context.Context, server, tool string, update func(old Pin, ok bool) (next Pin, save bool, err error)) (Pin, error)
}

// Auditor is the part of the store that writes the audit log.
type Auditor interface {
	AppendAudit(ctx context.Context, e audit.Entry) (audit.Entry, error)
}

// Options configures a Service.
type Options struct {
	Repo  Repository
	Audit Auditor
	// Server names the upstream this service pins tools for.
	Server string
	// AllowUnnamed lets calls through with arguments the pinned schema
	// doesn't name. Off, they're refused.
	AllowUnnamed bool
	Log          *slog.Logger
	Now          func() time.Time // nil means time.Now
}

// Service pins one server's tools. It is safe for concurrent use.
type Service struct {
	repo         Repository
	audit        Auditor
	server       string
	allowUnnamed bool
	log          *slog.Logger
	now          func() time.Time
}

// New builds a Service.
func New(opts Options) (*Service, error) {
	if opts.Repo == nil || opts.Audit == nil || opts.Log == nil || opts.Server == "" {
		return nil, errors.New("toolpin: Repo, Audit, Log and Server are required")
	}
	s := &Service{repo: opts.Repo, audit: opts.Audit, server: opts.Server, allowUnnamed: opts.AllowUnnamed, log: opts.Log, now: opts.Now}
	if s.now == nil {
		s.now = time.Now
	}
	return s, nil
}

// Server returns the name of the upstream the service pins tools for.
func (s *Service) Server() string { return s.server }

// definition is one tool from a listing.
type definition struct {
	name      string
	hash      string
	canonical json.RawMessage // the pinned fields, as canonical JSON
}

// parseDefinition reads one entry of a listing's tools list.
func parseDefinition(raw json.RawMessage) (definition, error) {
	// Decoding into a map would quietly keep one copy of a duplicate key,
	// and other parsers may keep the other.
	if _, err := verify.Canonicalize(raw); err != nil {
		return definition{}, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return definition{}, errors.New("is not an object")
	}
	var d definition
	if err := json.Unmarshal(fields["name"], &d.name); err != nil || d.name == "" {
		return definition{}, errors.New("has no name")
	}
	pinned := make(map[string]json.RawMessage, len(pinnedFields))
	for _, f := range pinnedFields {
		if v, ok := fields[f]; ok {
			pinned[f] = v
		}
	}
	encoded, err := json.Marshal(pinned)
	if err != nil {
		return definition{}, err
	}
	// Canonical, so a server that reorders keys or reformats numbers
	// hasn't changed anything.
	if d.canonical, err = verify.Canonicalize(encoded); err != nil {
		return definition{}, err
	}
	sum := sha256.Sum256(d.canonical)
	d.hash = "sha256:" + hex.EncodeToString(sum[:])
	return d, nil
}

// event is what one listing of a tool means for its pin.
type event int

const (
	unchanged    event = iota
	pinned             // seen for the first time
	changed            // differs from the pin, and from any change seen before
	stillChanged       // the change already seen
	reverted           // back to the pinned definition after a change
)

// next is what a pin becomes when d is listed: the rule every store
// applies inside UpdateToolPin.
func next(old Pin, ok bool, server string, d definition, at time.Time) (Pin, event) {
	switch {
	case !ok:
		return Pin{Server: server, Tool: d.name, Hash: d.hash, Definition: d.canonical, PinnedAt: at}, pinned
	case d.hash == old.Hash && old.Seen == "":
		return old, unchanged
	case d.hash == old.Hash:
		old.Seen, old.SeenDefinition, old.SeenAt = "", nil, time.Time{}
		return old, reverted
	case d.hash == old.Seen:
		return old, stillChanged
	default:
		old.Seen, old.SeenDefinition, old.SeenAt = d.hash, d.canonical, at
		return old, changed
	}
}

// Lister is who listed the tools, for the audit log.
type Lister struct{ AgentID, OwnerID string }

// ObserveList pins the tools in a tools/list result and returns the
// result to send the agent: changed tools left out, and so are entries
// that can't be pinned (not an object, no name, a duplicate key) and
// names listed twice with different definitions. When nothing is left
// out, it returns result exactly as it came.
//
// A result that isn't an object with a tools list is returned unchanged,
// for the client to make of it what it can. On an error, the listing must
// not reach the agent: its tools couldn't be checked.
func (s *Service) ObserveList(ctx context.Context, by Lister, result json.RawMessage) (json.RawMessage, error) {
	var top map[string]json.RawMessage
	var tools []json.RawMessage
	if json.Unmarshal(result, &top) != nil || json.Unmarshal(top["tools"], &tools) != nil {
		s.log.Warn("a tools/list result without a tools list passed unchecked", "server", s.server)
		return result, nil
	}
	defs := make([]definition, len(tools))
	hashes := map[string]map[string]bool{} // name -> the hashes listed under it
	for i, raw := range tools {
		d, err := parseDefinition(raw)
		if err != nil {
			s.log.Warn("left a tool out of the listing: it can't be pinned", "server", s.server, "entry", i, "err", err)
			continue
		}
		defs[i] = d
		if hashes[d.name] == nil {
			hashes[d.name] = map[string]bool{}
		}
		hashes[d.name][d.hash] = true
	}

	keep := make([]json.RawMessage, 0, len(tools))
	pins := map[string]Pin{}  // a name listed twice the same way is observed once
	done := map[string]bool{} // names already warned about
	for i, d := range defs {
		switch {
		case d.name == "":
			continue
		case len(hashes[d.name]) > 1:
			if !done[d.name] {
				s.log.Warn("left a tool out of the listing: it is listed twice, with different definitions", "server", s.server, "tool", d.name)
				done[d.name] = true
			}
			continue
		}
		p, seen := pins[d.name]
		if !seen {
			var err error
			if p, err = s.observe(ctx, by, d); err != nil {
				return nil, err
			}
			pins[d.name] = p
		}
		if !p.Changed() {
			keep = append(keep, tools[i])
		}
	}
	if len(keep) == len(tools) {
		return result, nil
	}
	var err error
	if top["tools"], err = marshalRaw(keep); err != nil {
		return nil, err
	}
	return marshalRaw(top)
}

// observe brings the pin of one listed tool up to date and returns it. A
// new pin or a change is written to the audit log first, so a failed save
// can only record it twice, never not at all.
func (s *Service) observe(ctx context.Context, by Lister, d definition) (Pin, error) {
	at := s.now().UTC()
	old, ok, err := s.repo.ToolPin(ctx, s.server, d.name)
	if err != nil {
		return Pin{}, fmt.Errorf("toolpin: %w", err)
	}
	_, ev := next(old, ok, s.server, d, at)
	switch ev {
	case unchanged, stillChanged:
		return old, nil
	case pinned:
		if err := s.record(ctx, by, d.name, audit.OutcomeToolPinned, "pinned "+d.hash+" the first time "+s.server+" listed it"); err != nil {
			return Pin{}, err
		}
	case changed:
		s.log.Warn("a tool's definition changed: it is left out of listings, and its calls ask, until the change is accepted",
			"server", s.server, "tool", d.name, "pinned", old.Hash, "now", d.hash, "accept_with", "consequenced -accept-tool "+d.name)
		if err := s.record(ctx, by, d.name, audit.OutcomeToolChanged, "definition changed from "+old.Hash+" to "+d.hash+"; its calls ask until it is accepted"); err != nil {
			return Pin{}, err
		}
	case reverted:
		s.log.Info("a changed tool is back to its pinned definition", "server", s.server, "tool", d.name, "hash", d.hash)
	}
	p, err := s.repo.UpdateToolPin(ctx, s.server, d.name, func(old Pin, ok bool) (Pin, bool, error) {
		p, ev := next(old, ok, s.server, d, at)
		return p, ev != unchanged && ev != stillChanged, nil
	})
	if err != nil {
		return Pin{}, fmt.Errorf("toolpin: %w", err)
	}
	return p, nil
}

func (s *Service) record(ctx context.Context, by Lister, tool string, outcome audit.Outcome, detail string) error {
	_, err := s.audit.AppendAudit(ctx, audit.Entry{
		Time: s.now().UTC(), AgentID: by.AgentID, OwnerID: by.OwnerID, Tool: tool, Outcome: outcome, Detail: detail,
	})
	if err != nil {
		return fmt.Errorf("toolpin: audit: %w", err)
	}
	return nil
}

// Status is what the service knows of a tool when it is called.
type Status int

const (
	Unpinned Status = iota // never listed, so nothing is known of it
	Pinned                 // listed as accepted
	Changed                // its last listing differed from the accepted definition
)

// Check looks up a called tool. For a pinned or changed tool, problem
// says how the arguments don't fit its accepted input schema, or is
// empty when they do. Unpinned tools aren't checked.
func (s *Service) Check(ctx context.Context, tool string, args map[string]any) (st Status, problem string, err error) {
	p, ok, err := s.repo.ToolPin(ctx, s.server, tool)
	if err != nil {
		return Unpinned, "", fmt.Errorf("toolpin: %w", err)
	}
	if !ok {
		return Unpinned, "", nil
	}
	st = Pinned
	if p.Changed() {
		st = Changed
	}
	if s.allowUnnamed {
		return st, "", nil
	}
	var def struct {
		InputSchema any `json:"inputSchema"`
	}
	if err := json.Unmarshal(p.Definition, &def); err != nil {
		return st, "", fmt.Errorf("toolpin: pinned definition of %s: %w", tool, err)
	}
	if path := unnamed(def.InputSchema, args, ""); path != "" {
		problem = fmt.Sprintf("argument %q is not in the input schema %s lists for %s", path, s.server, tool)
	}
	return st, problem, nil
}

// Accept makes the change last seen for server's tool its pinned
// definition, and writes that to the audit log. hash must be the change
// the person was shown, so a later change can't be accepted unseen.
//
// The acceptance is recorded before it is saved, so it is never saved
// unrecorded. If saving then fails, a not_applied entry follows it.
func Accept(ctx context.Context, repo Repository, log Auditor, server, tool, hash, by string, at time.Time) (Pin, error) {
	at = at.UTC()
	check := func(old Pin, ok bool) error {
		switch {
		case !ok:
			return fmt.Errorf("%s has no pin for %s", server, tool)
		case old.Seen == "":
			return fmt.Errorf("%s has no change waiting for %s", server, tool)
		case old.Seen != hash:
			return fmt.Errorf("%s changed %s again, to %s; look at it again before accepting it", server, tool, old.Seen)
		}
		return nil
	}
	old, ok, err := repo.ToolPin(ctx, server, tool)
	if err != nil {
		return Pin{}, fmt.Errorf("toolpin: %w", err)
	}
	if err := check(old, ok); err != nil {
		return Pin{}, err
	}
	entry := audit.Entry{Time: at, Tool: tool, Outcome: audit.OutcomeToolAccepted, Detail: "accepted " + hash + " for " + server + " by " + by}
	if _, err := log.AppendAudit(ctx, entry); err != nil {
		return Pin{}, fmt.Errorf("toolpin: audit: %w", err)
	}
	p, err := repo.UpdateToolPin(ctx, server, tool, func(old Pin, ok bool) (Pin, bool, error) {
		if err := check(old, ok); err != nil {
			return Pin{}, false, err
		}
		return Pin{Server: server, Tool: tool, Hash: old.Seen, Definition: old.SeenDefinition, PinnedAt: at, AcceptedBy: by}, true, nil
	})
	if err != nil {
		entry.Outcome, entry.Detail = audit.OutcomeNotApplied, "the acceptance before this wasn't saved: "+err.Error()
		_, _ = log.AppendAudit(ctx, entry)
		return Pin{}, err
	}
	return p, nil
}

// marshalRaw encodes without HTML escaping, so descriptions reach the
// agent as the server wrote them.
func marshalRaw(v any) (json.RawMessage, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
