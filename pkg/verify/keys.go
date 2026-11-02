package verify

import (
	"context"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// KeysPath is where ConsequenceOS publishes its public keys as a JWKS.
const KeysPath = "/.well-known/consequence-keys"

// JWK is one public key. Ed25519 keys use the OKP shape (RFC 8037 with the
// RFC 9864 "Ed25519" alg); ML-DSA keys use the AKP shape with "pub".
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	X   string `json:"x,omitempty"`   // Ed25519 public key
	Pub string `json:"pub,omitempty"` // ML-DSA public key
}

// JWKS is a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// KeyID derives a stable key ID from the algorithm and public key bytes,
// e.g. "ed25519-3f9a0c1d2e4b5a69".
func KeyID(alg string, pub []byte) string {
	sum := sha256.Sum256(pub)
	prefix := strings.ToLower(strings.ReplaceAll(alg, "-", ""))
	return prefix + "-" + hex.EncodeToString(sum[:8])
}

// Ed25519JWK builds the published form of an Ed25519 public key.
func Ed25519JWK(pub ed25519.PublicKey) JWK {
	return JWK{Kty: "OKP", Crv: "Ed25519", Alg: AlgEd25519, Kid: KeyID(AlgEd25519, pub), Use: "sig", X: b64.EncodeToString(pub)}
}

// MLDSA87JWK builds the published form of an ML-DSA-87 public key.
func MLDSA87JWK(pub *mldsa.PublicKey) JWK {
	raw := pub.Bytes()
	return JWK{Kty: "AKP", Alg: AlgMLDSA87, Kid: KeyID(AlgMLDSA87, raw), Use: "sig", Pub: b64.EncodeToString(raw)}
}

// KeySet holds the public keys a receiver trusts, by key ID.
type KeySet struct {
	ed25519 map[string]ed25519.PublicKey
	mldsa87 map[string]*mldsa.PublicKey
}

// ParseJWKS reads a JWKS document. Keys of other types are skipped.
func ParseJWKS(data []byte) (*KeySet, error) {
	var set JWKS
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("verify: bad JWKS: %w", err)
	}
	ks := &KeySet{ed25519: map[string]ed25519.PublicKey{}, mldsa87: map[string]*mldsa.PublicKey{}}
	for _, k := range set.Keys {
		switch {
		case k.Kty == "OKP" && k.Crv == "Ed25519" && k.Alg == AlgEd25519:
			raw, err := b64.DecodeString(k.X)
			if err != nil || len(raw) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("verify: bad Ed25519 key %q", k.Kid)
			}
			ks.ed25519[k.Kid] = ed25519.PublicKey(raw)
		case k.Kty == "AKP" && k.Alg == AlgMLDSA87:
			raw, err := b64.DecodeString(k.Pub)
			if err != nil {
				return nil, fmt.Errorf("verify: bad ML-DSA-87 key %q", k.Kid)
			}
			pub, err := mldsa.NewPublicKey(mldsa.MLDSA87(), raw)
			if err != nil {
				return nil, fmt.Errorf("verify: bad ML-DSA-87 key %q: %w", k.Kid, err)
			}
			ks.mldsa87[k.Kid] = pub
		}
	}
	if len(ks.ed25519) == 0 || len(ks.mldsa87) == 0 {
		return nil, fmt.Errorf("verify: JWKS needs at least one Ed25519 and one ML-DSA-87 key")
	}
	return ks, nil
}

// FetchKeys downloads and parses the JWKS from a ConsequenceOS server, e.g.
// FetchKeys(ctx, nil, "http://localhost:8080"). A nil client means http.DefaultClient.
func FetchKeys(ctx context.Context, client *http.Client, baseURL string) (*KeySet, error) {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(baseURL, "/")+KeysPath, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("verify: fetch keys: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("verify: fetch keys: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return ParseJWKS(data)
}
