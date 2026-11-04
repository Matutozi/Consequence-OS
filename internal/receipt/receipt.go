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
type Keys struct {
	ed      ed25519.PrivateKey
	edKid   string
	mldsa   *mldsa.PrivateKey
	mldsaID string
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
	return &Keys{
		ed:      ed,
		edKid:   verify.KeyID(verify.AlgEd25519, ed.Public().(ed25519.PublicKey)), // .(T) asserts the concrete type
		mldsa:   ml,
		mldsaID: verify.KeyID(verify.AlgMLDSA87, ml.PublicKey().Bytes()),
	}, nil
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

// JWKS returns the public keys in the form served at /.well-known/consequence-keys.
func (k *Keys) JWKS() verify.JWKS {
	return verify.JWKS{Keys: []verify.JWK{
		verify.Ed25519JWK(k.ed.Public().(ed25519.PublicKey)),
		verify.MLDSA87JWK(k.mldsa.PublicKey()),
	}}
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
	r := verify.Receipt{
		Type:       verify.ReceiptType,
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
	}
	encoded, err := i.sign(r)
	return encoded, r, err
}

func (i *Issuer) sign(r verify.Receipt) ([]byte, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	payload, err := verify.Canonicalize(raw) // the signed bytes are canonical, as the draft requires
	if err != nil {
		return nil, err
	}
	signed := verify.Signed{Payload: b64.EncodeToString(payload)}

	edHeader, err := protected(verify.AlgEd25519, i.keys.edKid)
	if err != nil {
		return nil, err
	}
	edSig := ed25519.Sign(i.keys.ed, verify.SigningInput(edHeader, signed.Payload))

	mlHeader, err := protected(verify.AlgMLDSA87, i.keys.mldsaID)
	if err != nil {
		return nil, err
	}
	mlSig, err := i.keys.mldsa.Sign(nil, verify.SigningInput(mlHeader, signed.Payload), nil)
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

func protected(alg, kid string) (string, error) {
	raw, err := json.Marshal(verify.ProtectedHeader{Typ: verify.MediaType, Alg: alg, Kid: kid})
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

// Checker is the server side of POST /v1/receipts/verify.
type Checker struct {
	keys *verify.KeySet
	used UsedStore
	now  func() time.Time
}

func NewChecker(keys *Keys, used UsedStore, now func() time.Time) (*Checker, error) {
	if now == nil {
		now = time.Now
	}
	jwks, err := json.Marshal(keys.JWKS())
	if err != nil {
		return nil, err
	}
	set, err := verify.ParseJWKS(jwks) // go through the public path, as a receiver would
	if err != nil {
		return nil, err
	}
	return &Checker{keys: set, used: used, now: now}, nil
}

// Verify checks everything, and marks the receipt used only when every
// other check has passed, so a bad request can't burn a good receipt.
func (c *Checker) Verify(ctx context.Context, encoded []byte, tool string, arguments []byte) (*verify.Receipt, error) {
	now := c.now()
	r, err := verify.VerifyOffline(encoded, c.keys, now)
	if err != nil {
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
