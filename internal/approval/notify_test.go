package approval

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log/slog"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/matutozi/consequence-os/internal/policy"
)

// fakeSMTP is a tiny SMTP server that accepts one message per connection
// and hands it to the test. It speaks just enough of RFC 5321 for net/smtp.
type fakeSMTP struct {
	addr string
	got  chan string // "MAIL FROM / RCPT TO / message"
}

func startFakeSMTP(t *testing.T) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fakeSMTP{addr: ln.Addr().String(), got: make(chan string, 4)}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
	return f
}

func (f *fakeSMTP) serve(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	say := func(line string) { _, _ = io.WriteString(conn, line+"\r\n") }
	say("220 fake ESMTP")
	var envelope, data strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			say("250 fake")
		case strings.HasPrefix(cmd, "MAIL FROM"), strings.HasPrefix(cmd, "RCPT TO"):
			envelope.WriteString(strings.TrimSpace(line) + "\n")
			say("250 ok")
		case cmd == "DATA":
			say("354 go ahead")
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				data.WriteString(l)
			}
			say("250 queued")
			f.got <- envelope.String() + "\n" + data.String()
		case cmd == "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func testNotice() Notice {
	return Notice{
		Approval: Approval{
			ID: "apr_0123456789abcdef", AgentID: "support-bot", OwnerID: "acme", Tool: "payments.refund",
			Arguments: []byte(`{"amount":5000,"charge_id":"ch_123"}`), Level: policy.LevelIrreversible, Rule: "big-refunds",
			ExpiresAt: time.Date(2026, 11, 2, 11, 0, 0, 0, time.UTC),
		},
		Approver: "ada@acme.example",
		Link:     "http://localhost:8080/approvals/apr_0123456789abcdef?token=secret-token-value",
		Validity: 10 * time.Minute,
	}
}

func TestEmailNotifierSends(t *testing.T) {
	srv := startFakeSMTP(t)
	var logs bytes.Buffer
	e, err := NewEmailNotifier("smtp://"+srv.addr, "approvals@acme.example", slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	e.sent = func(_ string, err error) { done <- err }

	e.Notify(context.Background(), testNotice())
	var raw string
	select {
	case raw = <-srv.got:
	case <-time.After(5 * time.Second):
		t.Fatal("no email arrived")
	}
	if err := <-done; err != nil {
		t.Fatalf("send: %v", err)
	}

	envelope, message, _ := strings.Cut(raw, "\n\n")
	if !strings.Contains(envelope, "<approvals@acme.example>") || !strings.Contains(envelope, "<ada@acme.example>") {
		t.Errorf("envelope = %q", envelope)
	}
	m, err := mail.ReadMessage(strings.NewReader(message))
	if err != nil {
		t.Fatalf("not a valid email: %v", err)
	}
	body, _ := io.ReadAll(quotedprintable.NewReader(m.Body))
	checks := []struct{ name, got, want string }{
		{"to", m.Header.Get("To"), "ada@acme.example"},
		{"subject", m.Header.Get("Subject"), "Approval needed: support-bot wants to run payments.refund"},
		{"sentence", string(body), "support-bot (owned by acme) wants to run payments.refund, an irreversible action."},
		{"amount", string(body), "amount: 5000"},
		{"link", string(body), testNotice().Link},
		{"window", string(body), "once within 10 minutes"},
		{"deadline", string(body), "If nobody decides by 11:00 UTC, 2 Nov 2026, the request expires."},
	}
	for _, c := range checks {
		if !strings.Contains(c.got, c.want) {
			t.Errorf("%s: %q does not contain %q", c.name, c.got, c.want)
		}
	}
	if strings.Contains(logs.String(), "secret-token-value") {
		t.Error("the email notifier logged the secret link")
	}
}

func TestEmailFailureIsLoggedWithoutLink(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close() // nothing listens here now

	var logs bytes.Buffer
	e, _ := NewEmailNotifier("smtp://"+addr, "approvals@acme.example", slog.New(slog.NewTextHandler(&logs, nil)))
	done := make(chan error, 1)
	e.sent = func(_ string, err error) { done <- err }
	e.Notify(context.Background(), testNotice())

	if err := <-done; err == nil {
		t.Fatal("expected a connection error")
	}
	if !strings.Contains(logs.String(), "approval email failed") || strings.Contains(logs.String(), "secret-token-value") {
		t.Errorf("log = %s", logs.String())
	}
}

func TestNewEmailNotifier(t *testing.T) {
	tests := []struct {
		name, url, from string
		wantAddr        string
		wantTLS         bool
		wantUser        string
		wantErr         bool
	}{
		{"starttls default port", "smtp://u:p@mail.example", "a@b.example", "mail.example:587", false, "u", false},
		{"implicit tls default port", "smtps://mail.example", "a@b.example", "mail.example:465", true, "", false},
		{"explicit port, no login", "smtp://mailpit:1025", "a@b.example", "mailpit:1025", false, "", false},
		{"wrong scheme", "http://mail.example", "a@b.example", "", false, "", true},
		{"no host", "smtp://", "a@b.example", "", false, "", true},
		{"bad from", "smtp://mail.example", "not-an-email", "", false, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := NewEmailNotifier(tt.url, tt.from, slog.Default())
			if tt.wantErr {
				if err == nil {
					t.Error("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if e.addr != tt.wantAddr || e.implicitTLS != tt.wantTLS || e.username != tt.wantUser {
				t.Errorf("got addr=%s tls=%v user=%q", e.addr, e.implicitTLS, e.username)
			}
		})
	}
}

func TestMessageHeadersCannotBeInjected(t *testing.T) {
	n := testNotice()
	n.Approval.Tool = "payments.refund\r\nBcc: attacker@evil.example"
	msg, err := buildMessage("approvals@acme.example", n, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	m, err := mail.ReadMessage(bytes.NewReader(msg))
	if err != nil {
		t.Fatal(err)
	}
	if m.Header.Get("Bcc") != "" {
		t.Error("a line break in a tool name created a Bcc header")
	}

	n = testNotice()
	n.Approver = "ada@acme.example\r\nBcc: attacker@evil.example"
	if _, err := buildMessage("approvals@acme.example", n, time.Now()); err == nil {
		t.Error("an approver address with a line break was accepted")
	}
}
