package proxy

import (
	"bytes"
	"io"
	"net/http"
	"strings"
)

// The upstream's token must never reach the agent, but an upstream can
// echo it: a debug error page that prints request headers, say. So with
// upstream_auth_env set, every response from the upstream has the token
// replaced with asterisks, in its headers and its body. The replacement is
// as long as the token, so Content-Length stays right.
//
// This catches the token as sent. A server that encodes it first (base64,
// say) gets past this, as it could get past any filter.

// redactHeaders replaces secret in every response header value.
func redactHeaders(h http.Header, secret string) {
	mask := strings.Repeat("*", len(secret))
	for name, values := range h {
		for i, v := range values {
			if strings.Contains(v, secret) {
				h[name][i] = strings.ReplaceAll(v, secret, mask)
			}
		}
	}
}

// redactor is a response body with secret replaced. It holds back only a
// tail that could be the start of the secret, so a streamed event (SSE)
// reaches the agent as soon as its last byte arrives.
type redactor struct {
	body    io.ReadCloser
	secret  []byte
	mask    []byte
	buf     []byte // for reading from body
	pending []byte // read, but might be the start of the secret
	out     []byte // ready for the caller
	err     error  // from body, returned once pending and out are drained
}

func newRedactor(body io.ReadCloser, secret string) *redactor {
	return &redactor{
		body: body, secret: []byte(secret), mask: bytes.Repeat([]byte("*"), len(secret)),
		buf: make([]byte, 32<<10),
	}
}

func (r *redactor) Read(p []byte) (int, error) {
	for len(r.out) == 0 {
		if r.err != nil {
			if len(r.pending) == 0 {
				return 0, r.err
			}
			r.out, r.pending = r.pending, nil // the stream ended: nothing more can complete the secret
			break
		}
		n, err := r.body.Read(r.buf)
		r.err = err
		data := bytes.ReplaceAll(append(r.pending, r.buf[:n]...), r.secret, r.mask)
		keep := 0
		if err == nil {
			keep = partialSuffix(data, r.secret)
		}
		r.out = data[:len(data)-keep]
		r.pending = append([]byte(nil), data[len(data)-keep:]...)
	}
	n := copy(p, r.out)
	r.out = r.out[n:]
	return n, nil
}

func (r *redactor) Close() error { return r.body.Close() }

// partialSuffix returns the length of the longest end of b that is the
// start of secret, but not all of it.
func partialSuffix(b, secret []byte) int {
	for k := min(len(b), len(secret)-1); k > 0; k-- {
		if bytes.HasSuffix(b, secret[:k]) {
			return k
		}
	}
	return 0
}
