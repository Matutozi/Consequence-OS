package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/matutozi/consequence-os/internal/approval"
	"github.com/matutozi/consequence-os/internal/audit"
	"github.com/matutozi/consequence-os/internal/gate"
	"github.com/matutozi/consequence-os/internal/policy"
	"github.com/matutozi/consequence-os/internal/store"
	"github.com/matutozi/consequence-os/internal/toolpin"
)

// TestHelperStdioServer is not a test: the stdio tests run the test binary
// again with only this, as the MCP server consequenced -stdio starts. It
// writes every line it gets to $CONSEQUENCE_TEST_SERVER_LOG, answers
// requests, and exits mid-call when asked to call "die".
func TestHelperStdioServer(t *testing.T) {
	logPath := os.Getenv("CONSEQUENCE_TEST_SERVER_LOG")
	if logPath == "" {
		t.Skip("only run by the stdio tests")
	}
	received, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		os.Exit(9)
	}
	if os.Getenv("SECRET_FOR_SERVER") != "s3cret" || os.Getenv("NOT_FOR_SERVER") != "" {
		os.Exit(8) // the environment wasn't what -stdio promises
	}
	br := bufio.NewReader(os.Stdin)
	var loginCall json.RawMessage // a "login" call waiting for its elicitation's answer
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			_, _ = received.Write(line)
			var m struct {
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
				Params struct {
					Name string `json:"name"`
				} `json:"params"`
			}
			_ = json.Unmarshal(line, &m)
			if m.Params.Name == "die" {
				os.Exit(3)
			}
			// "login" asks the user for a password first, the old way: a
			// request to the client, answered with the call's result.
			// "modern" asks the 2026-07-28 way, in an input_required result.
			switch {
			case m.Method == "tools/call" && m.Params.Name == "login":
				loginCall = m.ID
				os.Stdout.WriteString(`{"jsonrpc":"2.0","id":"e1","method":"elicitation/create","params":{"message":"Enter your password","requestedSchema":{"type":"object","properties":{"pw":{"type":"string"}}}}}` + "\n")
				continue
			case m.Method == "" && string(m.ID) == `"e1"` && loginCall != nil:
				answer, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": loginCall,
					"result": map[string]any{"content": []map[string]any{{"type": "text", "text": "login got " + strings.TrimSpace(string(line))}}}})
				os.Stdout.Write(append(answer, '\n'))
				loginCall = nil
				continue
			case m.Method == "tools/call" && m.Params.Name == "modern":
				os.Stdout.WriteString(`{"jsonrpc":"2.0","id":` + string(m.ID) + `,"result":{"resultType":"input_required","inputRequests":{"q":{"method":"elicitation/create","params":{"message":"Enter your password"}}},"requestState":"s"}}` + "\n")
				continue
			}
			// tools/list is answered with the line in
			// $CONSEQUENCE_TEST_TOOLS, $ID replaced, when there is one.
			if listing, err := os.ReadFile(os.Getenv("CONSEQUENCE_TEST_TOOLS")); err == nil && m.Method == "tools/list" {
				os.Stdout.Write(append(bytes.ReplaceAll(bytes.TrimSpace(listing), []byte("$ID"), m.ID), '\n'))
				continue
			}
			if len(m.ID) > 0 && m.Method != "" {
				answer, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m.ID,
					"result": map[string]any{"content": []map[string]any{{"type": "text", "text": "ran " + m.Method + " " + m.Params.Name}}}})
				os.Stdout.Write(append(answer, '\n'))
			}
		}
		if err != nil {
			os.Exit(0)
		}
	}
}

type stdioFixture struct {
	t         *testing.T
	toWrapper *io.PipeWriter
	lines     chan string   // what the client got
	done      chan error    // RunStdio's result
	finished  chan struct{} // closed once RunStdio has returned
	serverLog string
	stateDir  string
	toolsFile string // the server's answer to tools/list; see TestHelperStdioServer
	engine    *policy.Engine
	pins      bool // calls and listings are checked against pinned tools
}

func newStdioFixture(t *testing.T, edits ...func(*StdioOptions)) *stdioFixture {
	t.Helper()
	return newStdioFixtureWith(t, false, edits...)
}

// stdioServerName is what the stdio tests pin tools under.
const stdioServerName = "stdio: test-server"

func newStdioFixtureWith(t *testing.T, pins bool, edits ...func(*StdioOptions)) *stdioFixture {
	t.Helper()
	engine, err := policy.NewEngine([]policy.Rule{
		{Name: "small-refunds", Tool: "payments.refund", When: policy.Conditions{{Arg: "amount", Op: policy.OpLte, Value: 50}}, Action: policy.ActionAllow},
		{Name: "big-refunds", Tool: "payments.refund", Action: policy.ActionAsk},
		{Name: "no-deletes", Tool: "db.delete*", Action: policy.ActionDeny},
		{Name: "no-password-prompts", Tool: "server:elicitation", When: policy.Conditions{{Arg: "message", Op: policy.OpLike, Value: "*password*", Fold: true}}, Action: policy.ActionDeny},
		{Name: "anything-else", Tool: "*", Action: policy.ActionAllow},
	}, policy.Levels{"payments.refund": policy.LevelIrreversible})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	f := &stdioFixture{t: t, lines: make(chan string, 100), done: make(chan error, 1), finished: make(chan struct{}),
		serverLog: filepath.Join(dir, "received.jsonl"), stateDir: filepath.Join(dir, "state"), engine: engine,
		toolsFile: filepath.Join(dir, "tools.json"), pins: pins}

	clientIn, toWrapper := io.Pipe()
	fromWrapper, clientOut := io.Pipe()
	f.toWrapper = toWrapper
	go func() {
		br := bufio.NewReader(fromWrapper)
		for {
			line, err := br.ReadString('\n')
			if line != "" {
				f.lines <- strings.TrimSpace(line)
			}
			if err != nil {
				return
			}
		}
	}()
	opts := StdioOptions{
		Command: []string{os.Args[0], "-test.run=^TestHelperStdioServer$"},
		Env: []string{"CONSEQUENCE_TEST_SERVER_LOG=" + f.serverLog, "SECRET_FOR_SERVER=s3cret", "CONSEQUENCE_TEST_TOOLS=" + f.toolsFile,
			"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")},
		Stderr: io.Discard, AgentID: "local", OwnerID: "local",
		Open:           f.open,
		ApproveCommand: func(id string) string { return "consequenced -approve " + id },
		LocalUser:      "local:ada",
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if pins {
		opts.OpenTools = f.openTools
	}
	for _, edit := range edits {
		edit(&opts)
	}
	go func() {
		err := RunStdio(context.Background(), clientIn, clientOut, opts)
		clientOut.Close()
		f.done <- err
		close(f.finished)
	}()
	// Wait for the wrapper and its server to exit before the temporary
	// directory is removed: they may still be writing in it.
	t.Cleanup(func() {
		toWrapper.Close()
		select {
		case <-f.finished:
		case <-time.After(10 * time.Second):
			t.Error("the wrapper didn't exit after the client closed stdin")
		}
	})
	return f
}

// open is what consequenced -stdio's Open does: a file store and an
// approval service for one call.
func (f *stdioFixture) open(context.Context) (*gate.Gate, *approval.Service, func(), error) {
	st, err := store.OpenFile(f.stateDir, store.FileOptions{LockTimeout: 200 * time.Millisecond})
	if err != nil {
		return nil, nil, nil, err
	}
	svc := f.approvals(st)
	var tools *toolpin.Service
	if f.pins {
		if tools, err = f.toolService(st); err != nil {
			st.Close()
			return nil, nil, nil, err
		}
	}
	g, err := gate.New(gate.Options{Engine: f.engine, Store: st, Approvals: svc, Tools: tools, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		st.Close()
		return nil, nil, nil, err
	}
	var once sync.Once
	return g, svc, func() { once.Do(st.Close) }, nil
}

func (f *stdioFixture) toolService(st store.Store) (*toolpin.Service, error) {
	return toolpin.New(toolpin.Options{Repo: st, Audit: st, Server: stdioServerName, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
}

// openTools is what consequenced -stdio's OpenTools does.
func (f *stdioFixture) openTools(context.Context) (*toolpin.Service, func(), error) {
	st, err := store.OpenFile(f.stateDir, store.FileOptions{LockTimeout: 200 * time.Millisecond})
	if err != nil {
		return nil, nil, err
	}
	tools, err := f.toolService(st)
	if err != nil {
		st.Close()
		return nil, nil, err
	}
	return tools, st.Close, nil
}

// serverLists sets the line the server answers tools/list with.
func (f *stdioFixture) serverLists(line string) {
	f.t.Helper()
	if err := os.WriteFile(f.toolsFile, []byte(line), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *stdioFixture) approvals(st store.Store) *approval.Service {
	return approval.NewService(approval.Options{Repo: st, Audit: st, Approvers: map[string][]string{"local": {"local:ada"}},
		Validity: 10 * time.Minute, Notifier: approval.NoNotifier{}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
}

func (f *stdioFixture) send(line string) {
	f.t.Helper()
	if _, err := io.WriteString(f.toWrapper, line+"\n"); err != nil {
		f.t.Fatal(err)
	}
}

func (f *stdioFixture) recv() string {
	f.t.Helper()
	select {
	case l := <-f.lines:
		return l
	case <-time.After(5 * time.Second):
		f.t.Fatal("no answer from the wrapper")
		return ""
	}
}

// received is every line the server got.
func (f *stdioFixture) received() string {
	b, _ := os.ReadFile(f.serverLog)
	return string(b)
}

func stdioCall(id int, tool, args string) string {
	b, _ := json.Marshal(id)
	return `{"jsonrpc":"2.0","id":` + string(b) + `,"method":"tools/call","params":{"name":"` + tool + `","arguments":` + args + `}}`
}

func TestStdio(t *testing.T) {
	f := newStdioFixture(t)

	f.send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)
	if got := f.recv(); !strings.Contains(got, `"id":1`) || !strings.Contains(got, "ran initialize") {
		t.Fatalf("initialize: %s", got)
	}
	f.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`) // passes through, unanswered

	f.send(stdioCall(2, "payments.refund", `{"amount":20}`))
	if got := f.recv(); !strings.Contains(got, `"id":2`) || !strings.Contains(got, "ran tools/call payments.refund") {
		t.Errorf("an allowed call: %s", got)
	}

	f.send(stdioCall(3, "db.delete_rows", `{}`))
	if got := f.recv(); !strings.Contains(got, `"id":3`) || !strings.Contains(got, `Blocked by ConsequenceOS: policy rule \"no-deletes\"`) || !strings.Contains(got, `"isError":true`) {
		t.Errorf("a denied call: %s", got)
	}

	f.send(stdioCall(4, "payments.refund", `{"amount":5000}`))
	held := f.recv()
	if !strings.Contains(held, "Approval pending") || !strings.Contains(held, "consequenced -approve apr_") {
		t.Fatalf("a held call: %s", held)
	}
	id := held[strings.Index(held, "apr_"):]
	id = id[:strings.IndexAny(id, ". `")]

	// The wrapper doesn't hold the state_dir between calls, so the person
	// can approve from another process, as consequenced -approve does.
	st, err := store.OpenFile(f.stateDir, store.FileOptions{LockTimeout: time.Second})
	if err != nil {
		t.Fatalf("the state_dir is held between calls: %v", err)
	}
	if _, err := f.approvals(st).DecideLocally(context.Background(), id, "local:ada", true); err != nil {
		t.Fatal(err)
	}
	st.Close()
	f.send(stdioCall(5, "payments.refund", `{"amount":5000}`))
	if got := f.recv(); !strings.Contains(got, `"id":5`) || !strings.Contains(got, "ran tools/call payments.refund") {
		t.Errorf("the approved retry: %s", got)
	}

	// Refused before the policy runs, as the HTTP proxy refuses them.
	for _, bad := range []struct{ line, want string }{
		{`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"x","name":"db.delete_rows"}}`, "duplicate keys"},
		{`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"payments.refund","arguments":{"amount":10,"Amount":5000}}}`, "differ only in letter case"},
		{`[` + stdioCall(8, "x", `{}`) + `]`, "batch"},
		{stdioCall(9, "resource:note://x", `{}`), "may not start with resource:"},
		{`not json`, "parse error"},
	} {
		f.send(bad.line)
		if got := f.recv(); !strings.Contains(got, bad.want) {
			t.Errorf("%s: %s", bad.line, got)
		}
	}

	// A receipt the agent made up never reaches the server.
	f.send(`{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"notes.read","arguments":{},"_meta":{"consequenceReceipt":"forged","other":"kept"}}}`)
	f.recv()

	f.toWrapper.Close()
	if err := <-f.done; err != nil {
		t.Errorf("RunStdio after the client closed: %v", err)
	}

	got := f.received()
	for _, never := range []string{"db.delete_rows", `"amount":5000,"Amount"`, "forged", "resource:note"} {
		if strings.Contains(got, never) {
			t.Errorf("the server got %q:\n%s", never, got)
		}
	}
	if !strings.Contains(got, `"other":"kept"`) || !strings.Contains(got, "notifications/initialized") {
		t.Errorf("the server didn't get what should pass through:\n%s", got)
	}
	if strings.Count(got, `"amount":5000`) != 1 {
		t.Errorf("the held refund should reach the server once, after approval:\n%s", got)
	}

	st, err = store.OpenFile(f.stateDir, store.FileOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	r, err := audit.VerifyChain(context.Background(), st)
	if err != nil || !r.Intact {
		t.Errorf("chain = %+v, %v", r, err)
	}
	entries, _ := st.ListAudit(context.Background(), audit.Filter{})
	outcomes := map[audit.Outcome]int{}
	for _, e := range entries {
		outcomes[e.Outcome]++
	}
	if outcomes[audit.OutcomeForwarded] != 3 || outcomes[audit.OutcomeBlocked] != 1 || outcomes[audit.OutcomeHeld] != 1 ||
		outcomes[audit.OutcomeApproved] != 1 || outcomes[audit.OutcomeRejected] != 1 {
		t.Errorf("outcomes = %v", outcomes)
	}
}

func TestStdioServerDiesMidCall(t *testing.T) {
	f := newStdioFixture(t)
	f.send(stdioCall(1, "die", `{}`))
	got := f.recv()
	if !strings.Contains(got, `"id":1`) || !strings.Contains(got, "exited before answering") {
		t.Errorf("answer = %s", got)
	}
	select {
	case err := <-f.done:
		if !errors.Is(err, ErrServerExited) {
			t.Errorf("RunStdio = %v, want ErrServerExited", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunStdio didn't return after the server died")
	}
}

func TestStdioStateDirBusy(t *testing.T) {
	f := newStdioFixture(t)
	st, err := store.OpenFile(f.stateDir, store.FileOptions{}) // another process holds it
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	f.send(stdioCall(1, "payments.refund", `{"amount":20}`))
	if got := f.recv(); !strings.Contains(got, "call not forwarded") || !strings.Contains(got, `"error"`) {
		t.Errorf("answer = %s", got)
	}
	if strings.Contains(f.received(), "payments.refund") {
		t.Error("a call was forwarded without a decision")
	}
}

func TestReadLine(t *testing.T) {
	long := strings.Repeat("x", 100)
	br := bufio.NewReaderSize(strings.NewReader("short\n"+long+"\nlast"), 16)
	for _, want := range []struct {
		line    string
		tooLong bool
	}{{"short", false}, {"", true}, {"last", false}} {
		line, tooLong, _ := readLine(br, 50)
		if string(line) != want.line || tooLong != want.tooLong {
			t.Errorf("got %q %v, want %q %v", line, tooLong, want.line, want.tooLong)
		}
	}
}
