package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

// Concordium's Agent Registry is a smart contract implementing CIS-8004:
// every registered AI agent is an NFT, with an owner account, an optional
// Agent Card (a URL and the SHA-256 of the JSON served there) and a small
// on-chain key-value store. This file encodes the parameters of the
// entrypoints the tool calls, and decodes what they return, in the
// contract's binary format: little-endian integers, a u32 length before
// strings and byte vectors, and a 0 or 1 byte before optional values.
//
// The format isn't fully documented, so each encoding is pinned in
// registry_test.go to what the registry's own transaction builder produces
// and what the deployed contract returned on testnet.

// contractAddress is a smart contract instance on Concordium.
type contractAddress struct{ Index, Subindex uint64 }

func (c contractAddress) String() string { return fmt.Sprintf("<%d,%d>", c.Index, c.Subindex) }

// network is a Concordium chain the tool knows the registry's address on.
type network struct {
	Name string
	Node string // a public gRPC endpoint; it speaks TLS
	// Genesis is the first 16 bytes of the chain's genesis block hash, in
	// hex: the chain's CAIP-2 reference. The tool checks the node it talks
	// to is on this chain before reading or sending anything.
	Genesis     string
	Registry    contractAddress // CIS-8004, the Agent Registry
	KeyRegistry contractAddress // CIS-8, which binds keys of other chains to an account
	Explorer    string          // CCDScan
}

// The registry's addresses are Concordium's published ones; the genesis
// hashes were read from each network's node.
var networks = map[string]network{
	"testnet": {
		Name: "testnet", Node: "grpc.testnet.concordium.com:20000",
		Genesis:  "4221332d34e1694168c2a0c0b3fd0f27",
		Registry: contractAddress{12802, 0}, KeyRegistry: contractAddress{12801, 0},
		Explorer: "https://testnet.ccdscan.io",
	},
	"mainnet": {
		Name: "mainnet", Node: "grpc.mainnet.concordium.software:20000",
		Genesis:  "9dd9ca4d19e9393877d2c44b70f89acb",
		Registry: contractAddress{10082, 0}, KeyRegistry: contractAddress{10081, 0},
		Explorer: "https://ccdscan.io",
	},
}

// chainID is the network's CAIP-2 identifier, as Agent Cards use it.
func (n network) chainID() string { return "ccd:" + n.Genesis }

// txLink is the transaction's page on CCDScan.
func (n network) txLink(hash string) string {
	return n.Explorer + "/?dcount=1&dentity=transaction&dhash=" + hash
}

// The registry's limits on its key-value store, as the deployed contract
// enforces them. Measured on testnet: a longer value fails to parse, and
// a value with a zero byte in it is refused (error -7208). Keys may be up
// to 64 bytes, per the registry's documentation.
const (
	maxMetadataKey   = 64
	maxMetadataValue = 485
)

// Agent status, as agentOf returns it.
const (
	statusActive  = 0
	statusRevoked = 1
)

// tokenIDLen is the length byte of a CIS-2 TokenIdU64: the registry's
// token IDs are 8 bytes, little-endian, after this byte.
const tokenIDLen = 8

func appendTokenID(b []byte, id uint64) []byte {
	b = append(b, tokenIDLen)
	return binary.LittleEndian.AppendUint64(b, id)
}

func appendBytes(b, v []byte) []byte {
	b = binary.LittleEndian.AppendUint32(b, uint32(len(v)))
	return append(b, v...)
}

// registerParam is the parameter of register, which mints a new agent to
// the sender. uri is empty to register without a card, as is cardHash.
func registerParam(uri string, cardHash *[32]byte) []byte {
	var b []byte
	if uri == "" {
		b = append(b, 0)
	} else {
		b = appendBytes(append(b, 1), []byte(uri))
	}
	if cardHash == nil {
		b = append(b, 0)
	} else {
		b = append(append(b, 1), cardHash[:]...)
	}
	b = append(b, 0)                              // no external reference
	return binary.LittleEndian.AppendUint32(b, 0) // no initial metadata
}

// setAgentURIParam is the parameter of setAgentURI: where the agent's card
// is, and the SHA-256 of its bytes.
func setAgentURIParam(id uint64, uri string, cardHash [32]byte) []byte {
	b := appendTokenID(nil, id)
	b = appendBytes(append(b, 1), []byte(uri))
	return append(append(b, 1), cardHash[:]...)
}

// setMetadataParam is the parameter of setMetadata, which sets one key of
// the agent's on-chain store. It refuses what the contract would.
func setMetadataParam(id uint64, key string, value []byte) ([]byte, error) {
	switch {
	case key == "" || len(key) > maxMetadataKey:
		return nil, fmt.Errorf("a registry metadata key is 1 to %d bytes; %q is %d", maxMetadataKey, key, len(key))
	case len(value) > maxMetadataValue:
		return nil, fmt.Errorf("a registry metadata value is at most %d bytes; this one is %d", maxMetadataValue, len(value))
	case bytes.IndexByte(value, 0) >= 0:
		return nil, errors.New("the registry refuses a metadata value with a zero byte in it")
	}
	b := appendBytes(appendTokenID(nil, id), []byte(key))
	return appendBytes(b, value), nil
}

// getMetadataParam is the parameter of getMetadata.
func getMetadataParam(id uint64, key string) []byte {
	return appendBytes(appendTokenID(nil, id), []byte(key))
}

// reader reads the contract's binary format, failing on short input.
type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || len(r.b) < n {
		r.err = errors.New("the registry's answer ended early")
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) byte() byte {
	if v := r.take(1); v != nil {
		return v[0]
	}
	return 0
}

// option reads the 0 or 1 before an optional value.
func (r *reader) option() bool {
	switch r.byte() {
	case 0:
		return false
	case 1:
		return true
	}
	if r.err == nil {
		r.err = errors.New("the registry's answer has an optional value that is neither there nor not")
	}
	return false
}

func (r *reader) u32() uint32 {
	if v := r.take(4); v != nil {
		return binary.LittleEndian.Uint32(v)
	}
	return 0
}

func (r *reader) vec() []byte { return r.take(int(r.u32())) }

func (r *reader) tokenID() uint64 {
	if n := r.byte(); n != tokenIDLen && r.err == nil {
		r.err = fmt.Errorf("the registry's answer has a token ID of %d bytes; its IDs are %d", n, tokenIDLen)
	}
	if v := r.take(8); v != nil {
		return binary.LittleEndian.Uint64(v)
	}
	return 0
}

// account reads an account address's 32 bytes, as base58.
func (r *reader) account() string {
	if v := r.take(32); v != nil {
		return accountAddress(v)
	}
	return ""
}

// address reads an Address: an account's 32 bytes, or a contract's index
// and subindex. It returns the account in base58, or the contract.
func (r *reader) address() string {
	switch tag := r.byte(); tag {
	case 0:
		if v := r.take(32); v != nil {
			return accountAddress(v)
		}
	case 1:
		if v := r.take(16); v != nil {
			return contractAddress{binary.LittleEndian.Uint64(v), binary.LittleEndian.Uint64(v[8:])}.String()
		}
	default:
		if r.err == nil {
			r.err = fmt.Errorf("the registry's answer has an address of unknown kind %d", tag)
		}
	}
	return ""
}

// decodeMetadata reads what getMetadata returns: the value, if the key is
// set.
func decodeMetadata(ret []byte) (value []byte, ok bool, err error) {
	r := reader{b: ret}
	if ok = r.option(); ok {
		value = r.vec()
	}
	if r.err == nil && len(r.b) > 0 {
		r.err = errors.New("the registry's answer is longer than a metadata value")
	}
	return value, ok && r.err == nil, r.err
}

// agentRecord is what the registry holds about an agent.
type agentRecord struct {
	TokenID  uint64
	Owner    string    // the owning account, in base58
	CardURI  string    // "" when the agent has no card
	CardHash *[32]byte // nil when it has none
	Wallet   string    // the account payments go to, or ""
	Active   bool      // false once revoked
}

// decodeAgent reads what agentOf returns. ok is false when no agent has
// the ID. Fields after the status, such as when it was registered, are
// left unread, so that fields the contract adds later don't break it.
//
// An agent with an external reference (a key on another chain) can't be
// read: the reference's encoding isn't documented, and the fields after
// it can only be found by reading it.
func decodeAgent(ret []byte) (a agentRecord, ok bool, err error) {
	r := reader{b: ret}
	if !r.option() {
		if r.err == nil && len(r.b) > 0 {
			r.err = errors.New("the registry's answer is longer than no agent")
		}
		return a, false, r.err
	}
	a.TokenID = r.tokenID()
	a.Owner = r.account() // an account: agents are owned by accounts, so no address kind
	if r.option() {
		a.CardURI = string(r.vec())
	}
	if r.option() {
		if v := r.take(32); v != nil {
			a.CardHash = (*[32]byte)(bytes.Clone(v))
		}
	}
	if r.option() && r.err == nil {
		return a, false, errors.New("the agent has an external reference, which this tool can't read past")
	}
	if r.option() {
		a.Wallet = r.account()
	}
	switch status := r.byte(); {
	case r.err != nil:
	case status == statusActive:
		a.Active = true
	case status == statusRevoked:
	default:
		r.err = fmt.Errorf("the registry's answer has an agent status this tool doesn't know (%d)", status)
	}
	if r.err == nil && len(r.b) < 8 {
		r.err = errors.New("the registry's answer ended before the agent's registration time")
	}
	if r.err != nil {
		return agentRecord{}, false, r.err
	}
	return a, true, nil
}

// mintedTo finds, in a register transaction's contract events, the CIS-2
// mint event for owner (an account in base58) and returns its token ID.
// It's the answer to "which agent did my transaction create", read from
// the finalized transaction itself rather than from a dry run before it,
// which another registration could overtake.
func mintedTo(events [][]byte, owner string) (uint64, error) {
	const mintTag = 0xfe // CIS-2's Mint event
	var found []uint64
	for _, e := range events {
		if len(e) == 0 || e[0] != mintTag {
			continue
		}
		r := reader{b: e[1:]}
		id := r.tokenID()
		readLEB128(&r) // the amount: 1 for an NFT
		if to := r.address(); r.err == nil && to == owner {
			found = append(found, id)
		}
	}
	if len(found) != 1 {
		return 0, fmt.Errorf("the transaction minted %d agents to %s, not one", len(found), owner)
	}
	return found[0], nil
}

func readLEB128(r *reader) {
	for i := 0; i < 37; i++ { // CIS-2 amounts are at most 37 bytes of LEB128
		if r.byte()&0x80 == 0 || r.err != nil {
			return
		}
	}
	if r.err == nil {
		r.err = errors.New("the registry's answer has an amount longer than CIS-2 allows")
	}
}

// tokenAddress is the agent's CIS-2 token address in its short base58
// form: the badge a counterparty looks the agent up by.
func tokenAddress(c contractAddress, id uint64) string {
	b := binary.AppendUvarint(nil, c.Index) // LEB128, as Uvarint is
	b = binary.AppendUvarint(b, c.Subindex)
	b = binary.LittleEndian.AppendUint64(b, id)
	return base58Check(2, b)
}

// accountAddress is an account's 32 bytes in Concordium's base58 form.
func accountAddress(b []byte) string { return base58Check(1, b) }

// accountBytes reads an account address back into its 32 bytes.
func accountBytes(s string) ([]byte, error) {
	b, err := base58CheckDecode(s)
	if err != nil || len(b) != 33 || b[0] != 1 {
		return nil, fmt.Errorf("%q isn't a Concordium account address", s)
	}
	return b[1:], nil
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58Check is Bitcoin's Base58Check, which Concordium uses for account
// and token addresses: a version byte, the payload, and the first four
// bytes of a double SHA-256 as a checksum.
func base58Check(version byte, payload []byte) string {
	b := append([]byte{version}, payload...)
	sum := sha256.Sum256(b)
	sum = sha256.Sum256(sum[:])
	b = append(b, sum[:4]...)

	n := new(big.Int).SetBytes(b)
	var out []byte
	mod, base := new(big.Int), big.NewInt(58)
	for n.Sign() > 0 {
		n.DivMod(n, base, mod)
		out = append(out, base58Alphabet[mod.Int64()])
	}
	for _, c := range b { // each leading zero byte is a leading 1
		if c != 0 {
			break
		}
		out = append(out, '1')
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func base58CheckDecode(s string) ([]byte, error) {
	n := new(big.Int)
	base := big.NewInt(58)
	zeros := 0
	for i, c := range []byte(s) {
		d := bytes.IndexByte([]byte(base58Alphabet), c)
		if d < 0 {
			return nil, errors.New("not base58")
		}
		if d == 0 && i == zeros {
			zeros++
		}
		n.Mul(n, base).Add(n, big.NewInt(int64(d)))
	}
	b := append(make([]byte, zeros), n.Bytes()...)
	if len(b) < 5 {
		return nil, errors.New("too short")
	}
	body, check := b[:len(b)-4], b[len(b)-4:]
	sum := sha256.Sum256(body)
	sum = sha256.Sum256(sum[:])
	if !bytes.Equal(sum[:4], check) {
		return nil, errors.New("bad checksum")
	}
	return body, nil
}
