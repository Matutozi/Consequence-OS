package verify

import (
	"fmt"
	"strings"
)

// An audit head is ConsequenceOS's signed statement of where its audit
// log's hash chain ends: "entry Seq has hash Hash". It is signed like a
// receipt, with both keys, but under its own type, so neither can pass as
// the other. Anyone can check a head with the published keys; an auditor
// who saves heads over time can later prove the log before them was not
// rewritten.
const (
	AuditHeadType      = "consequenceos.audit-head.v0"          // the payload's "type"
	AuditHeadMediaType = "vnd.consequenceos.audit-head.v0+json" // each protected header's "typ"
)

// AuditHead is the signed payload.
type AuditHead struct {
	Type     string    `json:"type"`
	Issuer   string    `json:"issuer"`
	Seq      int64     `json:"seq"`  // the last entry's place in the log
	Hash     string    `json:"hash"` // that entry's chain hash, "sha256:..."
	SignedAt Timestamp `json:"signed_at"`
}

// VerifyAuditHead checks a signed head's encoding and both signatures.
// Heads don't expire: a saved head stays evidence of the log at that time.
func VerifyAuditHead(encoded []byte, keys *KeySet) (*AuditHead, error) {
	payload, err := verifiedPayload(encoded, keys, AuditHeadMediaType)
	if err != nil {
		return nil, err
	}
	var h AuditHead
	if err := decodeStrict(payload, &h); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if h.Type != AuditHeadType || h.Seq < 1 || !strings.HasPrefix(h.Hash, "sha256:") {
		return nil, fmt.Errorf("%w: missing or wrong type, seq or hash", ErrMalformed)
	}
	return &h, nil
}
