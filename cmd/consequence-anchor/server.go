package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/matutozi/consequence-os/pkg/verify"
)

// guardServer is the ConsequenceOS server whose audit log is anchored. It
// is reached the way an auditor would reach it: GET /v1/audit/head and
// GET /v1/audit/verify with the admin token, and the public keys.
type guardServer struct {
	base  string // its URL
	token string // the admin token
	http  *http.Client
}

// chainReport is the part of GET /v1/audit/verify's answer the tool reads.
type chainReport struct {
	Intact   bool   `json:"intact"`
	Checked  int    `json:"checked"`
	BrokenAt string `json:"broken_at"`
	Problem  string `json:"problem"`
	HeadSeq  int64  `json:"head_seq"`
	HeadHash string `json:"head_hash"`
}

// maxAnswer bounds what's read from the server or a card URL. A signed
// head is under 10 KB, and a card a few.
const maxAnswer = 1 << 20

func (s guardServer) get(ctx context.Context, path string, admin bool) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(s.base, "/")+path, nil)
	if err != nil {
		return nil, err
	}
	if admin {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	return fetch(s.http, req)
}

// fetch does req and returns the body of a 200 answer.
func fetch(c *http.Client, req *http.Request) ([]byte, error) {
	if c == nil {
		c = http.DefaultClient
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", req.URL.Redacted(), err)
	}
	if len(body) > maxAnswer {
		return nil, fmt.Errorf("%s answered with more than %d bytes", req.URL.Redacted(), maxAnswer)
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &e) == nil && e.Error != "" {
			return nil, fmt.Errorf("%s answered %d: %s", req.URL.Redacted(), resp.StatusCode, e.Error)
		}
		return nil, fmt.Errorf("%s answered %d", req.URL.Redacted(), resp.StatusCode)
	}
	return body, nil
}

// fetchURL GETs a public URL, such as an agent's card.
func fetchURL(ctx context.Context, c *http.Client, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	return fetch(c, req)
}

// head is the server's signed head of its audit log, as it serves it.
func (s guardServer) head(ctx context.Context) ([]byte, error) {
	return s.get(ctx, "/v1/audit/head", true)
}

// verifyChain has the server check its whole audit log and, when held is
// set, that the log still contains that anchored entry.
func (s guardServer) verifyChain(ctx context.Context, held *anchorValue) (chainReport, error) {
	path := "/v1/audit/verify"
	if held != nil {
		path += "?" + url.Values{"seq": {strconv.FormatInt(held.Seq, 10)}, "hash": {held.Hash}}.Encode()
	}
	body, err := s.get(ctx, path, true)
	if err != nil {
		return chainReport{}, err
	}
	var r chainReport
	if err := json.Unmarshal(body, &r); err != nil {
		return chainReport{}, fmt.Errorf("the server's chain check can't be read: %w", err)
	}
	return r, nil
}

// keys are the server's public keys.
func (s guardServer) keys(ctx context.Context) (*verify.KeySet, error) {
	return verify.FetchKeys(ctx, s.http, s.base)
}

// keysAt reads a JWKS from a full URL, such as the one an agent's card
// names.
func keysAt(ctx context.Context, c *http.Client, u string) (*verify.KeySet, error) {
	body, err := fetchURL(ctx, c, u)
	if err != nil {
		return nil, err
	}
	return verify.ParseJWKS(body)
}
