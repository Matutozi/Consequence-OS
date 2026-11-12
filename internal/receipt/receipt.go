// Package receipt issues signed consequence receipts and checks them for
// receivers. The format itself lives in pkg/verify, so issuing and verifying
// can never drift apart.
package receipt

import (
	"context"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/matutozi/consequence-os/pkg/verify"
)

var b64 = base64.RawURLEncoding.Strict()

// Keys is the server's signing key pair set. The private halves never
// leave the process; the public halves are published as a JWKS.
//
// After a rotation, Keys also holds the public keys the server signed with
// before (AddPrevious). Audit heads signed with them always verify, since a
// saved head is evidence for as long as it's kept. Until a set time they
// are also published and accepted for receipts, so receipts issued just
// before the rotation still work, and receivers can switch over.
type Keys struct {
	ed      ed25519.PrivateKey
	edKid   string
	mldsa   *mldsa.PrivateKey
	mldsaID string

	previous      []verify.JWK
	previousUntil time.Time
	// The key sets receipts are checked with: the current keys alone, and
	// with the previous ones. Kept up to date by LoadKeys and AddPrevious.
	current, all *verify.KeySet
}

// LoadKeys builds Keys from two base64url seeds (32 bytes each), as produced
// by GenerateSeeds and held in env vars.
func LoadKeys(ed25519Seed, mldsaSeed string) (*Keys, error) {
	edRaw, err := b64.DecodeString(ed25519Seed)
	if err != nil || len(edRaw) != ed25519.SeedSize {
		return nil, errors.New("receipt: Ed25519 key must be 32 bytes, base64url without padding")
	}
	mlRaw, err := b64.DecodeString(mldsaSeed)
	if err != nil || len(mlRaw) != mldsa.PrivateKeySize {
		return nil, errors.New("receipt: ML-DSA-87 key must be a 32 byte seed, base64url without padding")
	}
	ml, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), mlRaw)
	if err != nil {
		return nil, fmt.Errorf("receipt: ML-DSA-87 key: %w", err)
	}
	ed := ed25519.NewKeyFromSeed(edRaw)
	k := &Keys{
		ed:      ed,
		edKid:   verify.KeyID(verify.AlgEd25519, ed.Public().(ed25519.PublicKey)), // .(T) asserts the concrete type
		mldsa:   ml,
		mldsaID: verify.KeyID(verify.AlgMLDSA87, ml.PublicKey().Bytes()),
	}
	if k.current, err = keySet(k.JWKS()); err != nil {
		return nil, err
	}
	k.all = k.current
	return k, nil
}

// GenerateSeeds returns fresh random seeds for LoadKeys.
func GenerateSeeds() (ed25519Seed, mldsaSeed string, err error) {
	ed, ml := make([]byte, ed25519.SeedSize), make([]byte, mldsa.PrivateKeySize)
	if _, err := rand.Read(ed); err != nil {
		return "", "", err
	}
	if _, err := rand.Read(ml); err != nil {
		return "", "", err
	}
	return b64.EncodeToString(ed), b64.EncodeToString(ml), nil
}

// JWKS returns the public keys the server signs with now.
func (k *Keys) JWKS() verify.JWKS {
	return verify.JWKS{Keys: []verify.JWK{
		verify.Ed25519JWK(k.ed.Public().(ed25519.PublicKey)),
		verify.MLDSA87JWK(k.mldsa.PublicKey()),
	}}
}

// AddPrevious adds the public keys the server signed with before a
// rotation, as a JWKS. Until until, they are published beside the current
// keys and accepted for receipts; audit heads they signed verify always.
// Every key must be an Ed25519 or ML-DSA-87 key whose kid is the one
// ConsequenceOS derives from it, and none may be a current key.
func (k *Keys) AddPrevious(jwks []byte, until time.Time) error {
	if _, err := verify.ParseJWKS(jwks); err != nil {
		return fmt.Errorf("receipt: previous keys: %w", err)
	}
	var doc verify.JWKS
	if err := json.Unmarshal(jwks, &doc); err != nil {
		return fmt.Errorf("receipt: previous keys: %w", err)
	}
	seen := map[string]bool{k.edKid: true, k.mldsaID: true}
	for _, j := range doc.Keys {
		var alg string
		var pub []byte
		var err error
		switch {
		case j.Kty == "OKP" && j.Crv == "Ed25519" && j.Alg == verify.AlgEd25519:
			alg = verify.AlgEd25519
			pub, err = b64.DecodeString(j.X)
		case j.Kty == "AKP" && j.Alg == verify.AlgMLDSA87:
			alg = verify.AlgMLDSA87
			pub, err = b64.DecodeString(j.Pub)
		default:
			return fmt.Errorf("receipt: previous key %q is neither an Ed25519 nor an ML-DSA-87 key", j.Kid)
		}
		if err != nil || verify.KeyID(alg, pub) != j.Kid {
			return fmt.Errorf("receipt: previous key %q: its kid isn't the one derived from the key; copy keys as consequenced -jwks prints them", j.Kid)
		}
		if j.Kid == k.edKid || j.Kid == k.mldsaID {
			return fmt.Errorf("receipt: previous key %q is a current signing key; previous keys are the ones used before a rotation", j.Kid)
		}
		if seen[j.Kid] {
			continue // listed twice: once is enough
		}
		seen[j.Kid] = true
		k.previous = append(k.previous, j)
	}
	k.previousUntil = until
	var err error
	k.all, err = keySet(k.All())
	return err
}

// receiptKeys is the key set receipts are accepted from at now: the keys
// published then.
func (k *Keys) receiptKeys(now time.Time) *verify.KeySet {
	if now.Before(k.previousUntil) {
		return k.all
	}
	return k.current
}

// Published returns the keys to publish at now: the current keys, and the
// previous ones until their time is up. Receipts signed with any of them
// verify.
func (k *Keys) Published(now time.Time) verify.JWKS {
	set := k.JWKS()
	if now.Before(k.previousUntil) {
		set.Keys = append(set.Keys, k.previous...)
	}
	return set
}

// PublishedUntil is when the previous keys stop being published, or the
// zero time when there are none, or they already have.
func (k *Keys) PublishedUntil(now time.Time) time.Time {
	if len(k.previous) == 0 || !now.Before(k.previousUntil) {
		return time.Time{}
	}
	return k.previousUntil
}

// All returns every public key the server knows, current and previous,
// whatever the time: what audit heads are checked with, and what the next
// rotation's previous keys are.
func (k *Keys) All() verify.JWKS {
	set := k.JWKS()
	set.Keys = append(set.Keys, k.previous...)
	return set
}

// HeadKeys is the key set saved audit heads are checked with: every key
// the server has signed with.
func (k *Keys) HeadKeys() *verify.KeySet { return k.all }

// keySet parses jwks through the public path, as a receiver would.
func keySet(jwks verify.JWKS) (*verify.KeySet, error) {
	raw, err := json.Marshal(jwks)
	if err != nil {
		return nil, err
	}
	return verify.ParseJWKS(raw)
}

// Input is what a receipt says about one call.
type Input struct {
	AgentID    string
	OwnerID    string
	ApprovedBy string // empty unless a human approved
	Tool       string
	ParamsHash string
	Summary    string
	Level      string
	Policy     string

	// Audience is the receiver the call goes to. Setting it issues a v1
	// receipt, which then also needs Consequence; leaving it empty issues v0.
	Audience    string
	Consequence *verify.Consequence
}

// Issuer signs receipts.
type Issuer struct {
	keys   *Keys
	issuer string
	ttl    time.Duration
	now    func() time.Time
}

func NewIssuer(keys *Keys, issuer string, ttl time.Duration, now func() time.Time) *Issuer {
	if now == nil {
		now = time.Now
	}
	return &Issuer{keys: keys, issuer: issuer, ttl: ttl, now: now}
}

// Issue builds and signs a receipt. It returns the encoded JWS (compact JSON,
// ready for a header) and the receipt it contains.
func (i *Issuer) Issue(in Input) ([]byte, verify.Receipt, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, verify.Receipt{}, err
	}
	decision := verify.DecisionPolicyAllowed
	if in.ApprovedBy != "" {
		decision = verify.DecisionHumanApproved
	}
	issued := i.now().UTC().Truncate(time.Second)
	typ := verify.ReceiptType
	switch {
	case in.Audience != "" && in.Consequence == nil:
		return nil, verify.Receipt{}, errors.New("receipt: a v1 receipt needs a consequence")
	case in.Audience == "" && in.Consequence != nil:
		return nil, verify.Receipt{}, errors.New("receipt: a consequence needs an audience (v1)")
	case in.Audience != "":
		typ = verify.ReceiptTypeV1
	}
	r := verify.Receipt{
		Type:       typ,
		ReceiptID:  "rcpt_" + hex.EncodeToString(id),
		Issuer:     i.issuer,
		AgentID:    in.AgentID,
		OwnerID:    in.OwnerID,
		ApprovedBy: in.ApprovedBy,
		Decision:   decision,
		Action:     verify.Action{Tool: in.Tool, ParamsHash: in.ParamsHash, Summary: in.Summary},
		Level:      in.Level,
		Policy:     in.Policy,
		IssuedAt:   verify.Timestamp{Time: issued},
		ExpiresAt:  verify.Timestamp{Time: issued.Add(i.ttl)},

		Audience:    in.Audience,
		Consequence: in.Consequence,
	}
	encoded, err := i.sign(r)
	return encoded, r, err
}

// sign signs r under the media type that matches its version.
func (i *Issuer) sign(r verify.Receipt) ([]byte, error) {
	if r.Type == verify.ReceiptTypeV1 {
		return i.keys.signJSON(r, verify.MediaTypeV1)
	}
	return i.keys.signJSON(r, verify.MediaType)
}

// SignAuditHead signs a statement that the audit log's entry seq has hash,
// under the audit-head type (see verify.AuditHead).
func (k *Keys) SignAuditHead(issuer string, seq int64, hash string, at time.Time) ([]byte, error) {
	return k.signJSON(verify.AuditHead{
		Type: verify.AuditHeadType, Issuer: issuer, Seq: seq, Hash: hash,
		SignedAt: verify.Timestamp{Time: at.UTC().Truncate(time.Second)},
	}, verify.AuditHeadMediaType)
}

// signJSON signs v's canonical JSON with both keys, as a JWS in General
// JSON Serialization whose protected headers carry typ.
func (k *Keys) signJSON(v any, typ string) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	payload, err := verify.Canonicalize(raw) // the signed bytes are canonical, as the draft requires
	if err != nil {
		return nil, err
	}
	signed := verify.Signed{Payload: b64.EncodeToString(payload)}

	edHeader, err := protected(typ, verify.AlgEd25519, k.edKid)
	if err != nil {
		return nil, err
	}
	edSig := ed25519.Sign(k.ed, verify.SigningInput(edHeader, signed.Payload))

	mlHeader, err := protected(typ, verify.AlgMLDSA87, k.mldsaID)
	if err != nil {
		return nil, err
	}
	mlSig, err := k.mldsa.Sign(nil, verify.SigningInput(mlHeader, signed.Payload), nil)
	if err != nil {
		return nil, fmt.Errorf("receipt: ML-DSA-87 sign: %w", err)
	}

	// Ed25519 first, then ML-DSA-87: the order the draft uses and VerifyOffline expects.
	signed.Signatures = []verify.Signature{
		{Protected: edHeader, Signature: b64.EncodeToString(edSig)},
		{Protected: mlHeader, Signature: b64.EncodeToString(mlSig)},
	}
	return json.Marshal(signed)
}

func protected(typ, alg, kid string) (string, error) {
	raw, err := json.Marshal(verify.ProtectedHeader{Typ: typ, Alg: alg, Kid: kid})
	if err != nil {
		return "", err
	}
	return b64.EncodeToString(raw), nil
}

// UsedStore remembers which receipts have been used.
type UsedStore interface {
	// MarkReceiptUsed records the receipt as used, or returns
	// verify.ErrAlreadyUsed if it already was. Must be atomic.
	MarkReceiptUsed(ctx context.Context, receiptID string, usedAt, expiresAt time.Time) error
}

// Checker is the server side of POST /v1/receipts/verify. It accepts
// receipts signed with the keys published at the time: the current ones,
// and the previous ones until their time is up.
type Checker struct {
	keys *Keys
	used UsedStore
	now  func() time.Time
}

func NewChecker(keys *Keys, used UsedStore, now func() time.Time) (*Checker, error) {
	if now == nil {
		now = time.Now
	}
	if keys == nil || used == nil {
		return nil, errors.New("receipt: NewChecker needs keys and a used-receipt store")
	}
	return &Checker{keys: keys, used: used, now: now}, nil
}

// Verify checks everything for the receiver whose ID is receiver, and
// marks the receipt used only when every other check has passed, so a bad
// request can't burn a good receipt. That includes the audience: another
// receiver can't use up a v1 receipt that isn't for it.
func (c *Checker) Verify(ctx context.Context, receiver string, encoded []byte, tool string, arguments []byte) (*verify.Receipt, error) {
	now := c.now()
	r, err := verify.VerifyOffline(encoded, c.keys.receiptKeys(now), now)
	if err != nil {
		return nil, err
	}
	if err := verify.CheckAudience(r, receiver); err != nil {
		return nil, err
	}
	if err := verify.CheckAction(r, tool, arguments); err != nil {
		return nil, err
	}
	if err := c.used.MarkReceiptUsed(ctx, r.ReceiptID, now.UTC(), r.ExpiresAt.Time); err != nil {
		return nil, err
	}
	return r, nil
}
