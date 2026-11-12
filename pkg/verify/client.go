package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// VerifyPath is the ConsequenceOS endpoint that fully checks a receipt,
// including single use.
const VerifyPath = "/v1/receipts/verify"

// ErrUnauthorized means the verify endpoint did not accept the receiver's
// API key. It's a setup problem, not a receipt problem; the call is refused.
var ErrUnauthorized = errors.New("verify: the server did not accept this receiver's API key")

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
// is the full check: signatures, expiry, audience, tool, arguments and
// single use. The server knows the audience from this receiver's API key.
type Client struct {
	BaseURL string       // e.g. "http://localhost:8080"
	APIKey  string       // this receiver's key, listed under receivers in the server's config
	HTTP    *http.Client // nil means http.DefaultClient
}

// NewClient returns a Client with a 10 second timeout.
func NewClient(baseURL, apiKey string) *Client {
	return &Client{BaseURL: strings.TrimSuffix(baseURL, "/"), APIKey: apiKey, HTTP: &http.Client{Timeout: 10 * time.Second}}
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
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("verify: %w", err) // a network failure: the caller must refuse the action
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrUnauthorized
	}
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

// Offline verifies signatures, expiry, audience, tool and arguments with a
// local key set, without contacting the server. It cannot enforce single
// use; pair it with your own record of used receipt IDs if you rely on it alone.
//
// When the server rotates its keys, receipts start naming a key Keys
// doesn't have. With Refresh set, Offline then gets the keys again, at
// most once every RefreshEvery, and tries once more:
//
//	v := &verify.Offline{Keys: keys, Audience: "payments-api",
//		Refresh: func(ctx context.Context) (*verify.KeySet, error) {
//			return verify.FetchKeys(ctx, nil, "https://consequence.example")
//		}}
//
// Keys may start nil when Refresh is set: the first receipt fetches them.
// Use a pointer: Offline holds a lock while it swaps the keys.
type Offline struct {
	Keys *KeySet
	// Audience is this receiver's ID, as listed under receivers in the
	// server's config. v1 receipts for any other receiver are refused, and
	// without it every v1 receipt is.
	Audience string
	Now      func() time.Time // nil means time.Now
	// Refresh gets the server's keys again; nil never does.
	Refresh func(ctx context.Context) (*KeySet, error)
	// RefreshEvery is the least time between two refreshes; 0 means a
	// minute. It keeps receipts naming made-up keys from making Offline
	// fetch the keys over and over.
	RefreshEvery time.Duration

	mu          sync.Mutex
	refreshedAt time.Time
}

// Verify implements Verifier.
func (o *Offline) Verify(ctx context.Context, receipt []byte, tool string, arguments []byte) (*Receipt, error) {
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	receipt = trimQuotes(receipt)
	if o.keys() == nil && !o.refresh(ctx, now()) {
		return nil, fmt.Errorf("%w: no keys loaded", ErrUnknownKey)
	}
	r, err := VerifyOffline(receipt, o.keys(), now())
	if errors.Is(err, ErrUnknownKey) && o.refresh(ctx, now()) {
		r, err = VerifyOffline(receipt, o.keys(), now())
	}
	if err != nil {
		return nil, err
	}
	if err := CheckAudience(r, o.Audience); err != nil {
		return nil, err
	}
	if err := CheckAction(r, tool, arguments); err != nil {
		return nil, err
	}
	return r, nil
}

func (o *Offline) keys() *KeySet {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.Keys
}

// refresh gets the keys again, unless it did so less than RefreshEvery
// ago. It reports whether the keys were replaced. A failed fetch keeps
// the keys there were.
func (o *Offline) refresh(ctx context.Context, now time.Time) bool {
	if o.Refresh == nil {
		return false
	}
	every := o.RefreshEvery
	if every <= 0 {
		every = time.Minute
	}
	o.mu.Lock()
	if !o.refreshedAt.IsZero() && now.Sub(o.refreshedAt) < every {
		o.mu.Unlock()
		return false
	}
	o.refreshedAt = now // claimed before fetching, so concurrent misses fetch once
	o.mu.Unlock()

	keys, err := o.Refresh(ctx)
	if err != nil || keys == nil {
		return false
	}
	o.mu.Lock()
	o.Keys = keys
	o.mu.Unlock()
	return true
}

func emptyAsObject(args []byte) json.RawMessage {
	if t := bytes.TrimSpace(args); len(t) == 0 || string(t) == "null" {
		return json.RawMessage("{}")
	}
	return args
}
