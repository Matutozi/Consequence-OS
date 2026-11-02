package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// VerifyPath is the ConsequenceOS endpoint that fully checks a receipt,
// including single use.
const VerifyPath = "/v1/receipts/verify"

// VerifyRequest is the body of POST /v1/receipts/verify.
type VerifyRequest struct {
	Receipt   json.RawMessage `json:"receipt"`             // the Signed object, or a string holding it
	Tool      string          `json:"tool"`                // the tool the receiver is about to run
	Arguments json.RawMessage `json:"arguments,omitempty"` // the arguments exactly as received
}

// VerifyResponse is the answer.
type VerifyResponse struct {
	Valid   bool     `json:"valid"`
	Reason  string   `json:"reason,omitempty"`  // e.g. "expired"; see Reason
	Message string   `json:"message,omitempty"` // human-readable
	Receipt *Receipt `json:"receipt,omitempty"` // the verified receipt when valid
}

// Verifier checks that a receipt allows one exact tool call. Client
// (online, with single use) and Offline (signatures and expiry only) both
// satisfy it.
type Verifier interface {
	Verify(ctx context.Context, receipt []byte, tool string, arguments []byte) (*Receipt, error)
}

// Client verifies receipts with one call to the ConsequenceOS server. This
// is the full check: signatures, expiry, tool, arguments and single use.
type Client struct {
	BaseURL string       // e.g. "http://localhost:8080"
	HTTP    *http.Client // nil means a client with a 10 second timeout
}

func NewClient(baseURL string) *Client {
	return &Client{BaseURL: strings.TrimSuffix(baseURL, "/"), HTTP: &http.Client{Timeout: 10 * time.Second}}
}

// Verify implements Verifier. It marks the receipt used: call it only right
// before performing the action.
func (c *Client) Verify(ctx context.Context, receipt []byte, tool string, arguments []byte) (*Receipt, error) {
	body, err := json.Marshal(VerifyRequest{Receipt: trimQuotes(receipt), Tool: tool, Arguments: emptyAsObject(arguments)})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+VerifyPath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("verify: %w", err) // a network failure: the caller must refuse the action
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var out VerifyResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("verify: HTTP %d with unreadable body", resp.StatusCode)
	}
	if !out.Valid || out.Receipt == nil {
		return nil, ErrorForReason(out.Reason)
	}
	return out.Receipt, nil
}

// Offline verifies signatures, expiry, tool and arguments with a local key
// set, without contacting the server. It cannot enforce single use; pair it
// with your own record of used receipt IDs if you rely on it alone.
type Offline struct {
	Keys *KeySet
	Now  func() time.Time // nil means time.Now
}

// Verify implements Verifier.
func (o *Offline) Verify(_ context.Context, receipt []byte, tool string, arguments []byte) (*Receipt, error) {
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	r, err := VerifyOffline(trimQuotes(receipt), o.Keys, now())
	if err != nil {
		return nil, err
	}
	if err := CheckAction(r, tool, arguments); err != nil {
		return nil, err
	}
	return r, nil
}

func emptyAsObject(args []byte) json.RawMessage {
	if t := bytes.TrimSpace(args); len(t) == 0 || string(t) == "null" {
		return json.RawMessage("{}")
	}
	return args
}
