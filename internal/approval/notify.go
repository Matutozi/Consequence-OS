package approval

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/url"
	"strings"
	"time"
)

// Notice tells one approver about a held call.
type Notice struct {
	Approval Approval
	Approver string        // the email address being notified
	Link     string        // that approver's secret link
	Validity time.Duration // how long an approval stays usable
}

// Notifier delivers approver links. Implementations must not block for
// long: the agent's request is waiting.
type Notifier interface {
	Notify(ctx context.Context, n Notice)
}

// LogNotifier writes approver links to the server log. It is the fallback
// when no email is configured; the log then holds secrets, so treat it as such.
type LogNotifier struct{ Log *slog.Logger }

func (l LogNotifier) Notify(_ context.Context, n Notice) {
	l.Log.Warn("approval requested: send this link to the approver only",
		"approval_id", n.Approval.ID, "approver", n.Approver, "agent", n.Approval.AgentID,
		"tool", n.Approval.Tool, "rule", n.Approval.Rule, "approver_link", n.Link)
}

// EmailNotifier sends each approver their link by SMTP.
type EmailNotifier struct {
	host        string // for TLS verification
	addr        string // host:port
	implicitTLS bool   // smtps://: TLS from the first byte (usually port 465)
	username    string
	password    string
	from        string
	timeout     time.Duration
	log         *slog.Logger
	sent        func(to string, err error) // tests hook in here; nil normally
}

// NewEmailNotifier parses an SMTP URL:
//
//	smtp://user:pass@smtp.example.com:587   STARTTLS when the server offers it
//	smtps://user:pass@smtp.example.com:465  TLS from the start
//	smtp://mailpit:1025                      no login, e.g. a local test inbox
func NewEmailNotifier(rawURL, from string, log *slog.Logger) (*EmailNotifier, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" || (u.Scheme != "smtp" && u.Scheme != "smtps") {
		return nil, errors.New("email: SMTP URL must look like smtp://user:pass@host:587 or smtps://host:465")
	}
	if addr, err := mail.ParseAddress(from); err != nil || addr.Address != from {
		return nil, fmt.Errorf("email: from %q must be a plain email address", from)
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"smtp": "587", "smtps": "465"}[u.Scheme]
	}
	e := &EmailNotifier{
		host:        u.Hostname(),
		addr:        net.JoinHostPort(u.Hostname(), port),
		implicitTLS: u.Scheme == "smtps",
		from:        from,
		timeout:     30 * time.Second,
		log:         log,
	}
	if u.User != nil {
		e.username = u.User.Username()
		e.password, _ = u.User.Password()
	}
	return e, nil
}

// Notify sends the email in the background, so a slow mail server can't
// hold up the agent. Failures are logged without the link.
func (e *EmailNotifier) Notify(_ context.Context, n Notice) {
	msg, err := buildMessage(e.from, n, time.Now())
	if err != nil {
		e.log.Error("approval email not built", "approval_id", n.Approval.ID, "approver", n.Approver, "err", err)
		return
	}
	go func() {
		err := e.send(n.Approver, msg)
		if err != nil {
			e.log.Error("approval email failed", "approval_id", n.Approval.ID, "approver", n.Approver, "err", err)
		} else {
			e.log.Info("approval email sent", "approval_id", n.Approval.ID, "approver", n.Approver)
		}
		if e.sent != nil {
			e.sent(n.Approver, err)
		}
	}()
}

func (e *EmailNotifier) send(to string, msg []byte) error {
	dialer := &net.Dialer{Timeout: e.timeout}
	var conn net.Conn
	var err error
	if e.implicitTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", e.addr, &tls.Config{ServerName: e.host})
	} else {
		conn, err = dialer.Dial("tcp", e.addr)
	}
	if err != nil {
		return fmt.Errorf("connect %s: %w", e.addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(e.timeout)) // the whole conversation, not each step

	c, err := smtp.NewClient(conn, e.host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()

	if !e.implicitTLS {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(&tls.Config{ServerName: e.host}); err != nil {
				return fmt.Errorf("starttls: %w", err)
			}
		}
	}
	if e.username != "" {
		// PlainAuth itself refuses to send a password over an unencrypted
		// connection unless the server is on localhost.
		if err := c.Auth(smtp.PlainAuth("", e.username, e.password, e.host)); err != nil {
			return fmt.Errorf("login: %w", err)
		}
	}
	if err := c.Mail(e.from); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// buildMessage writes a plain-text email (RFC 5322) with a quoted-printable body.
func buildMessage(from string, n Notice, now time.Time) ([]byte, error) {
	if addr, err := mail.ParseAddress(n.Approver); err != nil || addr.Address != n.Approver {
		return nil, fmt.Errorf("approver %q is not a plain email address", n.Approver)
	}
	a := n.Approval
	// Strip line breaks so nothing in an ID can start a new header.
	subject := strings.NewReplacer("\r", " ", "\n", " ").Replace(
		fmt.Sprintf("Approval needed: %s wants to run %s", a.AgentID, a.Tool))
	id := make([]byte, 8)
	_, _ = rand.Read(id)
	domain := from[strings.LastIndex(from, "@")+1:]

	var msg bytes.Buffer
	headers := [][2]string{
		{"From", "ConsequenceOS <" + from + ">"},
		{"To", n.Approver},
		{"Subject", mime.QEncoding.Encode("utf-8", subject)},
		{"Date", now.Format(time.RFC1123Z)},
		{"Message-ID", "<" + a.ID + "." + hex.EncodeToString(id) + "@" + domain + ">"},
		{"MIME-Version", "1.0"},
		{"Content-Type", "text/plain; charset=utf-8"},
		{"Content-Transfer-Encoding", "quoted-printable"},
	}
	for _, h := range headers {
		fmt.Fprintf(&msg, "%s: %s\r\n", h[0], h[1])
	}
	msg.WriteString("\r\n")

	qp := quotedprintable.NewWriter(&msg)
	if _, err := qp.Write([]byte(emailBody(n))); err != nil {
		return nil, err
	}
	if err := qp.Close(); err != nil {
		return nil, err
	}
	return msg.Bytes(), nil
}

func emailBody(n Notice) string {
	a := n.Approval
	var b strings.Builder
	b.WriteString(sentence(a) + "\r\n\r\n")
	for _, row := range argRows(a.Arguments) {
		fmt.Fprintf(&b, "    %s: %s\r\n", row.Name, row.Value)
	}
	fmt.Fprintf(&b, "\r\nPolicy rule: %s\r\nApproval ID: %s\r\n\r\n", a.Rule, a.ID)
	fmt.Fprintf(&b, "Review it and approve or reject:\r\n%s\r\n\r\n", n.Link)
	fmt.Fprintf(&b, "This link is for %s only: anyone who has it can decide as you. "+
		"If you approve, the agent can make this exact call once within %s.\r\n", n.Approver, HumanDuration(n.Validity))
	return b.String()
}
