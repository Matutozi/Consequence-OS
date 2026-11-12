package approval

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/matutozi/consequence-os/internal/policy"
)

// Handlers serves the approval page and the decide endpoint.
type Handlers struct {
	svc *Service
	log *slog.Logger
}

// NewHandlers builds the approval pages. The service records each decision
// in the audit log before saving it.
func NewHandlers(svc *Service, log *slog.Logger) *Handlers {
	return &Handlers{svc: svc, log: log}
}

// Page serves GET /approvals/{id}. With ?token=<secret> it shows the
// Approve and Reject buttons; without it, it's a read-only status page.
func (h *Handlers) Page(w http.ResponseWriter, r *http.Request) {
	id, token := r.PathValue("id"), r.URL.Query().Get("token") // PathValue reads {id} from the route (Go 1.22+)
	a, approver, err := h.svc.View(r.Context(), id, token)
	if err != nil {
		h.fail(w, err)
		return
	}
	note := ""
	if token != "" && approver == "" {
		note = "This approver link is not valid, so you can only view this request."
	}
	h.render(w, http.StatusOK, a, approver, token, note)
}

// Decide serves POST /approvals/{id}/decide with form fields token and
// decision (approve or reject).
func (h *Handlers) Decide(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	var approve bool
	switch r.PostForm.Get("decision") {
	case "approve":
		approve = true
	case "reject":
	default:
		http.Error(w, "decision must be approve or reject", http.StatusBadRequest)
		return
	}

	a, err := h.svc.Decide(r.Context(), id, r.PostForm.Get("token"), approve)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.render(w, http.StatusOK, a, "", "", "")
}

func (h *Handlers) fail(w http.ResponseWriter, err error) {
	setPageHeaders(w)
	switch {
	case errors.Is(err, ErrNotFound):
		http.Error(w, "No approval with that ID.", http.StatusNotFound)
	case errors.Is(err, ErrBadToken):
		http.Error(w, "This approver link is not valid.", http.StatusForbidden)
	case errors.Is(err, ErrNotPending):
		http.Error(w, "This request has already been decided.", http.StatusConflict)
	case errors.Is(err, ErrNotRecorded):
		http.Error(w, "Your decision could not be recorded, so it was not made. Please try again in a moment.", http.StatusServiceUnavailable)
	case errors.Is(err, ErrExpired):
		http.Error(w, "This request expired before anyone decided. If the agent asks again, a new request is sent.", http.StatusGone)
	default:
		h.log.Error("approval handler", "err", err)
		http.Error(w, "Something went wrong.", http.StatusInternalServerError)
	}
}

// setPageHeaders locks the page down: no scripts, no framing (which stops
// clickjacking the Approve button), no caching, and no Referer leaking the token.
func setPageHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
}

type argRow struct{ Name, Value string }

type pageData struct {
	A         Approval
	Status    string
	Sentence  string
	Args      []argRow
	CanDecide bool
	Approver  string // who the viewer is deciding as
	Token     string
	Note      string
	Validity  string
	ValidTill string
	ExpiresAt string // when a pending request stops waiting
}

func (h *Handlers) render(w http.ResponseWriter, status int, a Approval, approver, token, note string) {
	now := h.svc.Now()
	data := pageData{
		A:         a,
		Status:    statusLabel(a, now),
		Sentence:  sentence(a),
		Args:      argRows(a.Arguments),
		CanDecide: approver != "" && a.Status == StatusPending && !a.Overdue(now),
		Approver:  approver,
		Token:     token,
		Note:      note,
		Validity:  HumanDuration(h.svc.Validity()),
	}
	if !a.ValidUntil.IsZero() {
		data.ValidTill = a.ValidUntil.Format("15:04 MST, 2 Jan 2006")
	}
	if !a.ExpiresAt.IsZero() {
		data.ExpiresAt = a.ExpiresAt.Format("15:04 MST, 2 Jan 2006")
	}
	// Render into a buffer first so a template error can't send half a page.
	var buf bytes.Buffer
	if err := pageTemplate.Execute(&buf, data); err != nil {
		h.fail(w, err)
		return
	}
	setPageHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

func statusLabel(a Approval, now time.Time) string {
	switch {
	case a.Expired(now), a.Overdue(now), a.Status == StatusExpired:
		return "expired"
	case a.Status == StatusUsed:
		return "approved and used"
	}
	return string(a.Status)
}

// sentence describes the action in plain words.
func sentence(a Approval) string {
	article := "a"
	if a.Level == policy.LevelIrreversible {
		article = "an"
	}
	if policy.IsRead(a.Tool) {
		return fmt.Sprintf("%s (owned by %s) wants to %s.", a.AgentID, a.OwnerID, wants(a))
	}
	return fmt.Sprintf("%s (owned by %s) wants to %s, %s %s action.", a.AgentID, a.OwnerID, wants(a), article, a.Level)
}

// wants says what the agent wants to do: "run payments.refund", or for
// reads "read file:///notes/a" or "get the prompt summarize".
func wants(a Approval) string {
	if uri, ok := strings.CutPrefix(a.Tool, policy.ResourcePrefix); ok {
		return "read " + uri
	}
	if name, ok := strings.CutPrefix(a.Tool, policy.PromptPrefix); ok {
		return "get the prompt " + name
	}
	if what, ok := strings.CutPrefix(a.Tool, policy.ServerPrefix); ok {
		return "let its MCP server " + ServerAsk(what)
	}
	return "run " + a.Tool
}

// ServerAsk says what a server request asks for, from the part of its
// name after "server:": "ask the user for input" for elicitation.
func ServerAsk(what string) string {
	switch what {
	case "elicitation":
		return "ask the user for input"
	case "sampling":
		return "have the client's model write a message"
	case "roots":
		return "list the client's roots, the folders it may use"
	}
	return "send the client a " + what + " request"
}

// argRows turns the canonical arguments into name/value rows, sorted by
// name. html/template escapes every value, so arguments can't inject HTML.
func argRows(raw json.RawMessage) []argRow {
	var args map[string]json.RawMessage
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil
	}
	rows := make([]argRow, 0, len(args))
	for name, v := range args {
		var s string
		if json.Unmarshal(v, &s) != nil { // not a string: show the JSON as is
			s = string(v)
		}
		rows = append(rows, argRow{Name: name, Value: s})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows
}

// HumanDuration prints 10m as "10 minutes" instead of Go's "10m0s".
func HumanDuration(d time.Duration) string {
	switch {
	case d%time.Hour == 0 && d >= time.Hour:
		return plural(int(d/time.Hour), "hour")
	case d%time.Minute == 0 && d >= time.Minute:
		return plural(int(d/time.Minute), "minute")
	}
	return d.String()
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

// html/template (not text/template) escapes values for HTML automatically.
var pageTemplate = template.Must(template.New("approval").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Approval {{.A.ID}} · ConsequenceOS</title>
<style>
  :root { color-scheme: light dark; --ink:#142029; --muted:#566573; --line:#d3dce3; --bg:#f2f5f7; --card:#fff;
          --ok:#2b7a4b; --no:#b2352d; --wait:#9a6300; }
  @media (prefers-color-scheme: dark) { :root { --ink:#e5ecf1; --muted:#93a2ae; --line:#27333c; --bg:#0e1418; --card:#151d23;
          --ok:#6fcf94; --no:#f08a80; --wait:#e9b54f; } }
  body { margin:0; padding:24px 16px; background:var(--bg); color:var(--ink); font:16px/1.5 system-ui, sans-serif; }
  main { max-width:560px; margin:0 auto; background:var(--card); border:1px solid var(--line); border-radius:12px; padding:24px; }
  h1 { font-size:1.3rem; margin:0 0 4px; }
  .status { display:inline-block; font-weight:600; font-size:.85rem; padding:2px 10px; border-radius:99px; border:1px solid currentColor; }
  .pending { color:var(--wait); } .approved, .approved.and.used { color:var(--ok); } .rejected, .expired { color:var(--no); }
  .sentence { font-size:1.1rem; margin:16px 0; }
  table { width:100%; border-collapse:collapse; margin:8px 0 16px; }
  th, td { text-align:left; padding:8px; border-bottom:1px solid var(--line); vertical-align:top; overflow-wrap:anywhere; }
  th { width:35%; color:var(--muted); font-weight:500; }
  .meta { color:var(--muted); font-size:.85rem; }
  .score { margin:0 0 4px; } .reasons { margin:0 0 16px; padding-left:20px; color:var(--muted); }
  .buttons { display:flex; gap:12px; margin-top:20px; }
  button { flex:1; font:inherit; font-weight:600; padding:12px; border-radius:8px; border:0; cursor:pointer; color:#fff; }
  .approve { background:#2b7a4b; } .reject { background:#b2352d; }
  .note { background:var(--bg); padding:10px 12px; border-radius:8px; }
</style>
</head>
<body>
<main>
  <h1>Approval request</h1>
  <span class="status {{.Status}}">{{.Status}}</span>
  <p class="sentence">{{.Sentence}}</p>
  {{if .A.Reasons}}
  <p class="score">Consequence score <strong>{{.A.Score}}</strong> of 100, because:</p>
  <ul class="reasons">{{range .A.Reasons}}<li>{{.}}</li>{{end}}</ul>
  {{end}}

  <table>
    <tr><th>Tool</th><td>{{.A.Tool}}</td></tr>
    <tr><th>Policy rule</th><td>{{.A.Rule}}</td></tr>
    {{range .Args}}<tr><th>{{.Name}}</th><td>{{.Value}}</td></tr>
    {{end}}
  </table>

  {{if .Note}}<p class="note">{{.Note}}</p>{{end}}

  {{if .CanDecide}}
    <p>You are deciding as <strong>{{.Approver}}</strong>. If you approve, the agent can make this exact call once within {{.Validity}}.</p>
    {{if .ExpiresAt}}<p class="note">If nobody decides by {{.ExpiresAt}}, this request expires.</p>{{end}}
    <form method="post" action="/approvals/{{.A.ID}}/decide" class="buttons">
      <input type="hidden" name="token" value="{{.Token}}">
      <button class="approve" name="decision" value="approve">Approve</button>
      <button class="reject" name="decision" value="reject">Reject</button>
    </form>
  {{else if eq .Status "pending"}}
    <p class="note">Waiting for an approver. The agent will retry once this is approved.</p>
  {{else if eq .Status "approved"}}
    <p class="note">Approved by {{.A.DecidedBy}}. The agent can make this call once, until {{.ValidTill}}.</p>
  {{else if eq .Status "rejected"}}
    <p class="note">Rejected by {{.A.DecidedBy}}. The call will not go through.</p>
  {{else if eq .Status "expired"}}
    {{if .A.DecidedBy}}<p class="note">Approved by {{.A.DecidedBy}}, but the agent didn't retry before {{.ValidTill}}. The call will not go through.</p>
    {{else}}<p class="note">Nobody decided before {{.ExpiresAt}}, so this request expired. The call will not go through.</p>{{end}}
  {{end}}

  <p class="meta">ID {{.A.ID}} · requested {{.A.CreatedAt.Format "15:04 MST, 2 Jan 2006"}} · params hash {{.A.ParamsHash}}</p>
</main>
</body>
</html>
`))
