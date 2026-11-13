package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/matutozi/consequence-os/pkg/verify"
)

// What goes on-chain, and the Agent Card that says what it means.

// anchorKey is the registry metadata key the audit head is anchored under.
const anchorKey = "consequenceos.audit_head"

// anchorValue is what's anchored: the place and chain hash of the audit
// log's newest entry, as a signed head named it, and the SHA-256 of that
// signed head. The whole signed head is about 6.6 KB, with its ML-DSA-87
// signature, and the registry holds at most 485 bytes, so the head itself
// is kept off-chain and matched to the anchor by its digest.
//
// What vouches for the anchor on-chain is the transaction: the registry
// lets only the agent's owner set its metadata, and the chain records
// when. Anyone holding the anchored entry's place and hash can later check
// the log still contains it; consequenced -verify-audit -audit-head does.
type anchorValue struct {
	Hash string `json:"hash"` // the entry's chain hash, sha256:...
	Head string `json:"head"` // the SHA-256 of the signed head, sha256:...
	Seq  int64  `json:"seq"`  // the entry's place in the log
}

var sha256Hex = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func (a anchorValue) check() error {
	if a.Seq < 1 || !sha256Hex.MatchString(a.Hash) || !sha256Hex.MatchString(a.Head) {
		return errors.New("an anchor names an entry (seq 1 or more), its hash and the head's, each sha256: and 64 lowercase hex digits")
	}
	return nil
}

// encodeAnchor is the anchor as canonical JSON, which reads plainly on
// CCDScan and comes out byte for byte the same for the same anchor.
func encodeAnchor(a anchorValue) ([]byte, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	return verify.Canonicalize(raw)
}

// decodeAnchor reads an anchor back from the registry, strictly: anything
// but exactly the three fields isn't one.
func decodeAnchor(b []byte) (anchorValue, error) {
	if _, err := verify.Canonicalize(b); err != nil {
		return anchorValue{}, fmt.Errorf("the anchored value isn't strict JSON: %w", err)
	}
	var a anchorValue
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&a); err != nil {
		return anchorValue{}, fmt.Errorf("the anchored value isn't an anchor: %w", err)
	}
	if d.More() {
		return anchorValue{}, errors.New("the anchored value has more after the anchor")
	}
	return a, a.check()
}

// digest is the SHA-256 of b, as sha256:... .
func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// The Agent Card is the agent's public description, in the A2A format,
// hosted wherever its owner likes; the registry pins its URL and SHA-256.
// Besides the Concordium badge block every registered agent's card has,
// this one carries ConsequenceOS's own extension, which says the agent is
// guarded, where the guard's public keys are, and which metadata key its
// audit head is anchored under. A counterparty reading the card from the
// registry learns all three from a source the agent's owner signed for.

// guardExtensionURI names the extension and its version; it's where the
// extension is documented.
const guardExtensionURI = "https://github.com/matutozi/consequence-os/blob/main/docs/concordium.md#agent-card-extension-v0"

type agentCard struct {
	Name               string       `json:"name"`
	Description        string       `json:"description"`
	URL                string       `json:"url"`
	Version            string       `json:"version"`
	DefaultInputModes  []string     `json:"defaultInputModes"`
	DefaultOutputModes []string     `json:"defaultOutputModes"`
	Authentication     cardAuth     `json:"authentication"`
	Skills             []cardSkill  `json:"skills"`
	Capabilities       capabilities `json:"capabilities"`
}

type cardAuth struct {
	Schemes []string `json:"schemes"`
}

type cardSkill struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
}

type capabilities struct {
	Streaming         bool        `json:"streaming"`
	PushNotifications bool        `json:"pushNotifications"`
	Extensions        []extension `json:"extensions"`
}

type extension struct {
	URI         string          `json:"uri"`
	Description string          `json:"description"`
	Required    bool            `json:"required"`
	Params      json.RawMessage `json:"params"`
}

// badgeParams is the Concordium badge block, as the registry's own card
// builder writes it.
type badgeParams struct {
	TokenAddress *string `json:"tokenAddress"`
	Owner        struct {
		Account string `json:"account"`
	} `json:"owner"`
	AgentWallet string `json:"agentWallet"`
	Contracts   struct {
		CIS8004 string `json:"cis8004"`
		CIS8    string `json:"cis8"`
	} `json:"contracts"`
	Verify       string `json:"verify"`
	Verification struct {
		Service   string `json:"service"`
		VerifyURL string `json:"verifyUrl,omitempty"`
		MCP       string `json:"mcp"`
		Docs      string `json:"docs"`
	} `json:"verification"`
}

// guardParams is ConsequenceOS's extension.
type guardParams struct {
	Issuer    string `json:"issuer"`    // the server's public URL, as its signed heads name it
	Keys      string `json:"keys"`      // its public keys, as a JWKS
	AnchorKey string `json:"anchorKey"` // the registry metadata key the audit head is anchored under
}

// cardInput is what the person gives for a card.
type cardInput struct {
	Name, Description string
	URL               string  // where the card will be hosted
	Owner             string  // the owning account, base58
	TokenID           *uint64 // nil before the agent is registered
	Issuer            string  // the ConsequenceOS server's public URL
	Net               network
}

// buildCard writes the card. The bytes it returns are the card: their
// SHA-256 is what the registry pins, so they must be hosted unchanged.
func buildCard(in cardInput) ([]byte, error) {
	if strings.TrimSpace(in.Name) == "" || strings.TrimSpace(in.Description) == "" {
		return nil, errors.New("a card needs a name and a description")
	}
	for what, u := range map[string]string{"the card's URL": in.URL, "the ConsequenceOS server's URL": in.Issuer} {
		if p, err := url.Parse(u); err != nil || p.Host == "" || (p.Scheme != "https" && p.Scheme != "http") {
			return nil, fmt.Errorf("%s must be an http or https URL, not %q", what, u)
		}
	}
	if _, err := accountBytes(in.Owner); err != nil {
		return nil, err
	}
	caip := func(s string) string { return in.Net.chainID() + ":" + s }

	var badge badgeParams
	if in.TokenID != nil {
		ta := tokenAddress(in.Net.Registry, *in.TokenID)
		badge.TokenAddress = &ta
		badge.Verification.VerifyURL = "https://agent-registry-mcp.concordium.com/v1/check-badge/" + ta
	}
	badge.Owner.Account = caip(in.Owner)
	badge.AgentWallet = caip(in.Owner)
	badge.Contracts.CIS8004 = caip(fmt.Sprintf("%d.%d", in.Net.Registry.Index, in.Net.Registry.Subindex))
	badge.Contracts.CIS8 = caip(fmt.Sprintf("%d.%d", in.Net.KeyRegistry.Index, in.Net.KeyRegistry.Subindex))
	badge.Verify = "Resolve tokenAddress via CIS-8004 agent_of; confirm owner + status=Active + card SHA-256 == metadata_hash."
	badge.Verification.Service = "Concordium Agent Registry"
	badge.Verification.MCP = "https://agent-registry-mcp.concordium.com/mcp"
	badge.Verification.Docs = "https://docs.concordium.com/en/mainnet/technical-reference/agent-registry/concordium-badge.html"

	issuer := strings.TrimSuffix(in.Issuer, "/")
	guard := guardParams{Issuer: issuer, Keys: issuer + verify.KeysPath, AnchorKey: anchorKey}

	badgeJSON, err := json.Marshal(badge)
	if err != nil {
		return nil, err
	}
	guardJSON, err := json.Marshal(guard)
	if err != nil {
		return nil, err
	}
	card := agentCard{
		Name: in.Name, Description: in.Description, URL: in.URL, Version: "1.0.0",
		DefaultInputModes:  []string{"text/markdown", "application/json"},
		DefaultOutputModes: []string{"text/markdown", "application/json"},
		Authentication:     cardAuth{Schemes: []string{}},
		Skills:             []cardSkill{},
		Capabilities: capabilities{Extensions: []extension{
			{
				URI:         "https://docs.concordium.com/a2a-extensions/concordium-badge/v1",
				Description: "Verified by Concordium badge — on-chain agent identity in a CIS-8004 registry",
				Params:      badgeJSON,
			},
			{
				URI:         guardExtensionURI,
				Description: "Guarded by ConsequenceOS: every tool call is decided by policy and recorded in a hash-chained audit log, whose head is anchored in this agent's registry metadata",
				Params:      guardJSON,
			},
		}},
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(card); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// readGuard finds ConsequenceOS's extension in a card. ok is false when
// the card has none: the agent doesn't say it's guarded.
func readGuard(card []byte) (g guardParams, ok bool, err error) {
	var c struct {
		Capabilities struct {
			Extensions []extension `json:"extensions"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(card, &c); err != nil {
		return g, false, fmt.Errorf("the card isn't JSON: %w", err)
	}
	for _, e := range c.Capabilities.Extensions {
		if e.URI != guardExtensionURI {
			continue
		}
		if ok {
			return g, false, errors.New("the card has ConsequenceOS's extension twice")
		}
		d := json.NewDecoder(bytes.NewReader(e.Params))
		d.DisallowUnknownFields()
		if err := d.Decode(&g); err != nil {
			return g, false, fmt.Errorf("the card's ConsequenceOS extension can't be read: %w", err)
		}
		if g.Issuer == "" || g.Keys == "" || g.AnchorKey == "" {
			return g, false, errors.New("the card's ConsequenceOS extension leaves out the issuer, keys or anchorKey")
		}
		ok = true
	}
	return g, ok, nil
}
