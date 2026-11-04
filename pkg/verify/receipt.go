package verify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Receipt format. A receipt is our own record (the IETF Agent Permission
// Receipts draft has no server-issued receipt), encoded the way that draft
// encodes records: a JWS in General JSON Serialization over an RFC 8785
// canonical payload, signed with both Ed25519 and ML-DSA-87.
const (
	ReceiptType = "consequenceos.receipt.v0"          // the payload's "type"
	MediaType   = "vnd.consequenceos.receipt.v0+json" // each protected header's "typ"
	AlgEd25519  = "Ed25519"                           // RFC 9864 name
	AlgMLDSA87  = "ML-DSA-87"                         // FIPS 204, post-quantum

	// HeaderName carries the receipt on the HTTP request to the receiver.
	HeaderName = "X-Consequence-Receipt"
	// MetaKey carries the same receipt in the MCP request's params._meta.
	MetaKey = "consequenceReceipt"

	DecisionHumanApproved = "human_approved"
	DecisionPolicyAllowed = "policy_allowed"

	// MaxClockSkew tolerates receivers whose clocks run slightly behind ours.
	MaxClockSkew = 30 * time.Second
)

// Reasons a receipt is refused. Each is a sentinel error, so callers can
// test with errors.Is, and Reason maps it to a stable code for APIs.
var (
	ErrMalformed      = errors.New("receipt is malformed")
	ErrUnknownKey     = errors.New("receipt is signed with an unknown key")
	ErrBadSignature   = errors.New("receipt signature does not verify")
	ErrNotCanonical   = errors.New("receipt payload is not canonical JSON")
	ErrExpired        = errors.New("receipt has expired")
	ErrNotYetValid    = errors.New("receipt is dated in the future")
	ErrToolMismatch   = errors.New("receipt is for a different tool")
	ErrParamsMismatch = errors.New("receipt does not match these arguments")
	ErrAlreadyUsed    = errors.New("receipt has already been used")
	ErrMissing        = errors.New("no receipt was provided")
)

var reasons = map[error]string{
	ErrMalformed: "malformed", ErrUnknownKey: "unknown_key", ErrBadSignature: "bad_signature",
	ErrNotCanonical: "not_canonical", ErrExpired: "expired", ErrNotYetValid: "not_yet_valid",
	ErrToolMismatch: "tool_mismatch", ErrParamsMismatch: "params_mismatch",
	ErrAlreadyUsed: "already_used", ErrMissing: "missing",
}

// Reason returns the stable code for a receipt error, e.g. "expired".
func Reason(err error) string {
	for sentinel, code := range reasons {
		if errors.Is(err, sentinel) {
			return code
		}
	}
	return "invalid"
}

// ErrorForReason is the inverse of Reason, for API clients.
func ErrorForReason(code string) error {
	for sentinel, c := range reasons {
		if c == code {
			return sentinel
		}
	}
	return fmt.Errorf("receipt rejected (%s)", code)
}

// Receipt is the signed statement that one exact action was allowed. Every
// receipt works once, so there is no field saying so. The payload holds
// only strings and objects, which fits the IETF draft's content rules
// (objects, arrays, strings and non-negative integers; no booleans or null).
type Receipt struct {
	Type       string    `json:"type"`
	ReceiptID  string    `json:"receipt_id"`
	Issuer     string    `json:"issuer"`
	AgentID    string    `json:"agent_id"`
	OwnerID    string    `json:"owner_id"`
	ApprovedBy string    `json:"approved_by"` // empty for policy_allowed
	Decision   string    `json:"decision"`
	Action     Action    `json:"action"`
	Level      string    `json:"level"`
	Policy     string    `json:"policy"` // the rule that decided
	IssuedAt   Timestamp `json:"issued_at"`
	ExpiresAt  Timestamp `json:"expires_at"`
}

// Action is the exact call the receipt covers.
type Action struct {
	Tool       string `json:"tool"`
	ParamsHash string `json:"params_hash"` // ParamsHash of the arguments
	Summary    string `json:"summary"`
}

// Timestamp is a time written as RFC 3339 in UTC with whole seconds,
// e.g. "2026-11-02T10:14:00Z", the time format the IETF draft uses.
type Timestamp struct{ time.Time }

const timestampLayout = "2006-01-02T15:04:05Z"

func (t Timestamp) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.UTC().Truncate(time.Second).Format(timestampLayout))
}

func (t *Timestamp) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	parsed, err := time.Parse(timestampLayout, s)
	if err != nil {
		return fmt.Errorf("time %q must look like 2026-11-02T10:14:00Z", s)
	}
	t.Time = parsed
	return nil
}

// Signed is the JWS General JSON Serialization (RFC 7515 section 7.2.1).
type Signed struct {
	Payload    string      `json:"payload"`
	Signatures []Signature `json:"signatures"`
}

// Signature is one entry of Signed.Signatures.
type Signature struct {
	Protected string `json:"protected"`
	Signature string `json:"signature"`
}

// ProtectedHeader is the decoded "protected" member. Field order here is the
// order of the encoded JSON: typ, alg, kid.
type ProtectedHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// b64 is base64url without padding, decoded strictly (RFC 4648 section 5).
var b64 = base64.RawURLEncoding.Strict()

// SigningInput is what each signature covers: ASCII(protected) "." ASCII(payload).
func SigningInput(protected, payload string) []byte {
	return []byte(protected + "." + payload)
}

// VerifyOffline checks a receipt's encoding and both signatures against
// keys, and that it is currently valid. It does not check single use; only
// the issuer can, through POST /v1/receipts/verify (see Client).
func VerifyOffline(encoded []byte, keys *KeySet, now time.Time) (*Receipt, error) {
	var signed Signed
	if err := decodeStrict(encoded, &signed); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if err := verifySignatures(signed, keys); err != nil {
		return nil, err
	}

	payload, err := b64.DecodeString(signed.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: payload is not base64url", ErrMalformed)
	}
	// The signed bytes must already be canonical; we check, never rewrite.
	if canonical, err := Canonicalize(payload); err != nil || !bytes.Equal(canonical, payload) {
		return nil, ErrNotCanonical
	}
	var r Receipt
	if err := decodeStrict(payload, &r); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if r.Type != ReceiptType || r.ReceiptID == "" || r.Action.Tool == "" || r.Action.ParamsHash == "" {
		return nil, fmt.Errorf("%w: missing or wrong type, receipt_id or action", ErrMalformed)
	}

	switch {
	case !now.Before(r.ExpiresAt.Time):
		return nil, ErrExpired
	case r.IssuedAt.After(now.Add(MaxClockSkew)):
		return nil, ErrNotYetValid
	}
	return &r, nil
}

// verifySignatures requires exactly one Ed25519 signature followed by one
// ML-DSA-87 signature, both by known keys, both valid.
func verifySignatures(signed Signed, keys *KeySet) error {
	want := []string{AlgEd25519, AlgMLDSA87}
	if len(signed.Signatures) != len(want) {
		return fmt.Errorf("%w: want %d signatures, got %d", ErrMalformed, len(want), len(signed.Signatures))
	}
	for i, sig := range signed.Signatures {
		header, err := decodeHeader(sig.Protected)
		if err != nil {
			return err
		}
		if header.Typ != MediaType || header.Alg != want[i] {
			return fmt.Errorf("%w: signature %d must be typ %s, alg %s", ErrMalformed, i+1, MediaType, want[i])
		}
		raw, err := b64.DecodeString(sig.Signature)
		if err != nil {
			return fmt.Errorf("%w: signature %d is not base64url", ErrMalformed, i+1)
		}
		input := SigningInput(sig.Protected, signed.Payload)

		switch header.Alg {
		case AlgEd25519:
			pub, ok := keys.ed25519[header.Kid]
			if !ok {
				return fmt.Errorf("%w: %s", ErrUnknownKey, header.Kid)
			}
			if len(raw) != ed25519.SignatureSize || !ed25519.Verify(pub, input, raw) {
				return fmt.Errorf("%w (Ed25519)", ErrBadSignature)
			}
		case AlgMLDSA87:
			pub, ok := keys.mldsa87[header.Kid]
			if !ok {
				return fmt.Errorf("%w: %s", ErrUnknownKey, header.Kid)
			}
			if err := mldsa.Verify(pub, input, raw, nil); err != nil {
				return fmt.Errorf("%w (ML-DSA-87)", ErrBadSignature)
			}
		}
	}
	return nil
}

func decodeHeader(protected string) (ProtectedHeader, error) {
	raw, err := b64.DecodeString(protected)
	if err != nil {
		return ProtectedHeader{}, fmt.Errorf("%w: protected header is not base64url", ErrMalformed)
	}
	var h ProtectedHeader
	if err := decodeStrict(raw, &h); err != nil {
		return ProtectedHeader{}, fmt.Errorf("%w: protected header: %v", ErrMalformed, err)
	}
	return h, nil
}

// CheckAction confirms a valid receipt covers this tool and these exact
// arguments (as received, before any processing).
func CheckAction(r *Receipt, tool string, arguments []byte) error {
	if r.Action.Tool != tool {
		return ErrToolMismatch
	}
	hash, err := ParamsHash(arguments)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrParamsMismatch, err)
	}
	if hash != r.Action.ParamsHash {
		return ErrParamsMismatch
	}
	return nil
}

// decodeStrict decodes one JSON value and rejects unknown fields, duplicate
// keys and trailing data.
func decodeStrict(data []byte, v any) error {
	if _, err := Canonicalize(data); err != nil { // catches duplicates and trailing data
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// trimQuotes accepts a receipt passed either as a JSON object or as a JSON
// string containing one.
func trimQuotes(raw []byte) []byte {
	raw = bytes.TrimSpace(raw)
	if len(raw) > 0 && raw[0] == '"' {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return []byte(strings.TrimSpace(s))
		}
	}
	return raw
}
