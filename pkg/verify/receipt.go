package verify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Receipt format. A receipt is our own record (the IETF Agent Permission
// Receipts draft has no server-issued receipt), encoded the way that draft
// encodes records: a JWS in General JSON Serialization over an RFC 8785
// canonical payload, signed with both Ed25519 and ML-DSA-87.
//
// There are two versions. v1 adds the receiver the receipt is for
// (Audience) and how serious the action is (Consequence). Verifiers decode
// payloads strictly, so a new field needs a new version: verifiers accept
// both, and the server switches to v1 one release after they do.
const (
	ReceiptType = "consequenceos.receipt.v0"          // v0: the payload's "type"
	MediaType   = "vnd.consequenceos.receipt.v0+json" // v0: each protected header's "typ"

	ReceiptTypeV1 = "consequenceos.receipt.v1"          // v1: the payload's "type"
	MediaTypeV1   = "vnd.consequenceos.receipt.v1+json" // v1: each protected header's "typ"

	AlgEd25519 = "Ed25519"   // RFC 9864 name
	AlgMLDSA87 = "ML-DSA-87" // FIPS 204, post-quantum

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
	ErrWrongAudience  = errors.New("receipt is for a different receiver")
)

var reasons = map[error]string{
	ErrMalformed: "malformed", ErrUnknownKey: "unknown_key", ErrBadSignature: "bad_signature",
	ErrNotCanonical: "not_canonical", ErrExpired: "expired", ErrNotYetValid: "not_yet_valid",
	ErrToolMismatch: "tool_mismatch", ErrParamsMismatch: "params_mismatch",
	ErrAlreadyUsed: "already_used", ErrMissing: "missing", ErrWrongAudience: "wrong_audience",
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
	Audience   string    `json:"audience,omitempty"` // v1: the receiver ID it's for; empty in v0
	AgentID    string    `json:"agent_id"`
	OwnerID    string    `json:"owner_id"`
	ApprovedBy string    `json:"approved_by"` // empty for policy_allowed
	Decision   string    `json:"decision"`
	Action     Action    `json:"action"`
	Level      string    `json:"level"`
	Policy     string    `json:"policy"` // the rule that decided
	IssuedAt   Timestamp `json:"issued_at"`
	ExpiresAt  Timestamp `json:"expires_at"`

	Consequence *Consequence `json:"consequence,omitempty"` // v1: how serious the action is; nil in v0
}

// Consequence says how serious the action a v1 receipt covers is, as
// ConsequenceOS judged it when it decided. Only strings and a non-negative
// integer, to fit the draft's content rules.
type Consequence struct {
	Score         int    `json:"score"`              // 0 (harmless) to 100 (worst)
	Reversibility string `json:"reversibility"`      // one of the Reversibility constants
	Source        string `json:"source"`             // SourceConfig or SourceMap
	MapHash       string `json:"map_hash,omitempty"` // which consequence map judged it, when Source is SourceMap
}

// Values for Consequence.Reversibility and Consequence.Source.
const (
	ReversibilityRead        = "read"        // changes nothing
	ReversibilityReversible  = "reversible"  // can be undone directly
	ReversibilityCompensable = "compensable" // a named call can undo its effect
	ReversibilityNone        = "none"        // can't be undone

	SourceConfig = "config" // from the tools listed in consequence.yaml
	SourceMap    = "map"    // from a consequence map of the system
)

// MaxScore is the highest consequence score.
const MaxScore = 100

// validate checks the fields a verifier may rely on.
func (c *Consequence) validate() error {
	switch {
	case c.Score < 0 || c.Score > MaxScore:
		return fmt.Errorf("consequence score %d is outside 0 to %d", c.Score, MaxScore)
	case !slices.Contains([]string{ReversibilityRead, ReversibilityReversible, ReversibilityCompensable, ReversibilityNone}, c.Reversibility):
		return fmt.Errorf("unknown consequence reversibility %q", c.Reversibility)
	case c.Source != SourceConfig && c.Source != SourceMap:
		return fmt.Errorf("unknown consequence source %q", c.Source)
	case c.Source == SourceMap && !strings.HasPrefix(c.MapHash, "sha256:"):
		return errors.New("a consequence from a map needs its map_hash")
	case c.Source == SourceConfig && c.MapHash != "":
		return errors.New("a consequence from config has no map_hash")
	}
	return nil
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
// keys, and that it is currently valid. It accepts v0 and v1 receipts. It
// checks neither the audience (see CheckAudience) nor single use; only the
// issuer can check single use, through POST /v1/receipts/verify (see Client).
func VerifyOffline(encoded []byte, keys *KeySet, now time.Time) (*Receipt, error) {
	payload, typ, err := verifiedPayload(encoded, keys, MediaType, MediaTypeV1)
	if err != nil {
		return nil, err
	}
	var r Receipt
	if err := decodeStrict(payload, &r); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if r.ReceiptID == "" || r.Action.Tool == "" || r.Action.ParamsHash == "" {
		return nil, fmt.Errorf("%w: missing receipt_id or action", ErrMalformed)
	}
	if err := checkVersion(&r, typ); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	switch {
	case !now.Before(r.ExpiresAt.Time):
		return nil, ErrExpired
	case r.IssuedAt.After(now.Add(MaxClockSkew)):
		return nil, ErrNotYetValid
	}
	return &r, nil
}

// checkVersion makes sure the payload's type matches the protected
// headers' typ, and that each version carries exactly its own fields: a v0
// receipt never names an audience, and a v1 receipt always does.
func checkVersion(r *Receipt, typ string) error {
	switch {
	case typ == MediaType && r.Type == ReceiptType:
		if r.Audience != "" || r.Consequence != nil {
			return errors.New("a v0 receipt has no audience or consequence")
		}
	case typ == MediaTypeV1 && r.Type == ReceiptTypeV1:
		if r.Audience == "" || r.Consequence == nil {
			return errors.New("a v1 receipt needs an audience and a consequence")
		}
		return r.Consequence.validate()
	default:
		return fmt.Errorf("payload type %q doesn't match header typ %q", r.Type, typ)
	}
	return nil
}

// CheckAudience confirms a valid receipt is for this receiver: audience is
// the receiver's ID, as listed under receivers in the server's config. A v1
// receipt names exactly one receiver; a v0 receipt names none and passes,
// until v0 support is removed.
func CheckAudience(r *Receipt, audience string) error {
	if r.Type == ReceiptType {
		return nil
	}
	if audience == "" {
		return fmt.Errorf("%w: this receiver has no audience set, so it can't accept v1 receipts", ErrWrongAudience)
	}
	if r.Audience != audience {
		return fmt.Errorf("%w: it is for %q", ErrWrongAudience, r.Audience)
	}
	return nil
}

// verifiedPayload checks a signed object's encoding and both signatures,
// requiring the protected headers to say one of typs (all the same one),
// and returns the canonical payload and that typ. The typ check keeps a
// signed audit head from passing as a receipt, and the other way round.
func verifiedPayload(encoded []byte, keys *KeySet, typs ...string) ([]byte, string, error) {
	var signed Signed
	if err := decodeStrict(encoded, &signed); err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if len(signed.Signatures) == 0 {
		return nil, "", fmt.Errorf("%w: no signatures", ErrMalformed)
	}
	first, err := decodeHeader(signed.Signatures[0].Protected)
	if err != nil {
		return nil, "", err
	}
	if !slices.Contains(typs, first.Typ) {
		return nil, "", fmt.Errorf("%w: unexpected typ %q", ErrMalformed, first.Typ)
	}
	typ := first.Typ
	if err := verifySignatures(signed, keys, typ); err != nil { // every signature must say the same typ
		return nil, "", err
	}
	payload, err := b64.DecodeString(signed.Payload)
	if err != nil {
		return nil, "", fmt.Errorf("%w: payload is not base64url", ErrMalformed)
	}
	// The signed bytes must already be canonical; we check, never rewrite.
	if canonical, err := Canonicalize(payload); err != nil || !bytes.Equal(canonical, payload) {
		return nil, "", ErrNotCanonical
	}
	return payload, typ, nil
}

// verifySignatures requires exactly one Ed25519 signature followed by one
// ML-DSA-87 signature, both by known keys, both valid.
func verifySignatures(signed Signed, keys *KeySet, typ string) error {
	want := []string{AlgEd25519, AlgMLDSA87}
	if len(signed.Signatures) != len(want) {
		return fmt.Errorf("%w: want %d signatures, got %d", ErrMalformed, len(want), len(signed.Signatures))
	}
	for i, sig := range signed.Signatures {
		header, err := decodeHeader(sig.Protected)
		if err != nil {
			return err
		}
		if header.Typ != typ || header.Alg != want[i] {
			return fmt.Errorf("%w: signature %d must be typ %s, alg %s", ErrMalformed, i+1, typ, want[i])
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
