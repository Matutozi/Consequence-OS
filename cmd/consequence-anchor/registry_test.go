package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v2 "github.com/Concordium/concordium-go-sdk/v2"
)

// The vectors below were captured on 13 November 2026: parameters from the
// registry's own transaction builder (agent-registry-mcp.concordium.com,
// build_register, build_set_agent_uri, build_set_metadata, token_address),
// and answers from the deployed CIS-8004 contract <12802,0> on testnet.

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fill(b byte) *[32]byte {
	var h [32]byte
	for i := range h {
		h[i] = b
	}
	return &h
}

func TestParametersMatchTheRegistrysBuilder(t *testing.T) {
	tests := []struct {
		name string
		got  []byte
		want string
	}{
		{"register with a card", registerParam("https://example.org/card.json", fill(0xab)),
			"011d00000068747470733a2f2f6578616d706c652e6f72672f636172642e6a736f6e01abababababababababababababababababababababababababababababababab0000000000"},
		{"setAgentURI", setAgentURIParam(300, "https://e.org/c", *fill(0xcd)),
			"082c01000000000000010f00000068747470733a2f2f652e6f72672f6301cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"},
		// The builder's own example was the value 00 ff; the same layout
		// with a value the registry accepts.
		{"getMetadata", getMetadataParam(0, "consequenceos.audit_head"),
			"08000000000000000018000000" + hex.EncodeToString([]byte("consequenceos.audit_head"))},
	}
	for _, tt := range tests {
		if got := hex.EncodeToString(tt.got); got != tt.want {
			t.Errorf("%s:\n got %s\nwant %s", tt.name, got, tt.want)
		}
	}
	// register with no card: three absent options and no metadata.
	if got := hex.EncodeToString(registerParam("", nil)); got != "00000000000000" {
		t.Errorf("register without a card: %s", got)
	}
	got, err := setMetadataParam(0, "consequenceos.audit_head", []byte{0x41, 0xff})
	if err != nil {
		t.Fatal(err)
	}
	// From the builder: 08 + id, u32 key length, key, u32 value length, value.
	if want := "08000000000000000018000000636f6e73657175656e63656f732e61756469745f68656164020000" + "0041ff"; hex.EncodeToString(got) != want {
		t.Errorf("setMetadata:\n got %x\nwant %s", got, want)
	}
}

func TestSetMetadataRefusesWhatTheRegistryWould(t *testing.T) {
	if _, err := setMetadataParam(1, "k", bytes.Repeat([]byte{'a'}, maxMetadataValue)); err != nil {
		t.Errorf("a value of %d bytes, the most the registry takes: %v", maxMetadataValue, err)
	}
	for name, tc := range map[string]struct {
		key   string
		value []byte
		want  string
	}{
		"value too long": {"k", bytes.Repeat([]byte{'a'}, maxMetadataValue+1), "at most 485 bytes"},
		"zero byte":      {"k", []byte{'a', 0, 'b'}, "zero byte"},
		"empty key":      {"", []byte{'a'}, "1 to 64 bytes"},
		"key too long":   {strings.Repeat("k", maxMetadataKey+1), []byte{'a'}, "1 to 64 bytes"},
	} {
		if _, err := setMetadataParam(1, tc.key, tc.value); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want an error with %q", name, err, tc.want)
		}
	}
}

// liveAgent is agentOf(0) on testnet: owner and wallet 3dt3UMPz..., a
// card, no external reference, active, then the registration time and
// six more bytes.
const liveAgent = "010800000000000000005b22021a5a27dc3a25d9cde2887e208f818b5a55dcfc6b2c3c0271634ab331c9014f00000068747470733a2f2f74697070696e67736572766963652e636f2e756b2f6167656e74732f71756965745f6c65646765725f36332f2e77656c6c2d6b6e6f776e2f6167656e742d636172642e6a736f6e01e1299b4e1de23375342f4d2de6d19858d5d02217b4a87a526aa06deb539fc1fc00015b22021a5a27dc3a25d9cde2887e208f818b5a55dcfc6b2c3c0271634ab331c900c9200e679e010000000000000000"

const liveOwner = "3dt3UMPzRASZndjmKpSWgCP2HhmoxZrgs8FDPtZjNHZzj13hhB"

func TestDecodeAgent(t *testing.T) {
	a, ok, err := decodeAgent(unhex(t, liveAgent))
	if err != nil || !ok {
		t.Fatalf("got %v, %v", ok, err)
	}
	want := agentRecord{TokenID: 0, Owner: liveOwner, Wallet: liveOwner, Active: true,
		CardURI: "https://tippingservice.co.uk/agents/quiet_ledger_63/.well-known/agent-card.json"}
	if a.CardHash == nil || hex.EncodeToString(a.CardHash[:]) != "e1299b4e1de23375342f4d2de6d19858d5d02217b4a87a526aa06deb539fc1fc" {
		t.Errorf("card hash %x", a.CardHash)
	}
	a.CardHash = nil
	if a != want {
		t.Errorf("got %+v\nwant %+v", a, want)
	}

	if _, ok, err := decodeAgent(unhex(t, "00")); ok || err != nil {
		t.Errorf("no agent: got %v, %v", ok, err)
	}

	live := unhex(t, liveAgent)
	statusAt := len(live) - 15 // the status, the registration time, then 6 more bytes
	revoked := bytes.Clone(live)
	revoked[statusAt] = statusRevoked
	if a, ok, err := decodeAgent(revoked); !ok || err != nil || a.Active {
		t.Errorf("revoked: got %+v, %v, %v", a, ok, err)
	}

	unknown := bytes.Clone(live)
	unknown[statusAt] = 7
	extRef := bytes.Clone(live)
	extRef[statusAt-34] = 1 // the external reference, before the wallet
	for name, b := range map[string][]byte{
		"empty":                 {},
		"cut short":             live[:40],
		"no registration time":  live[:statusAt+1],
		"unknown status":        unknown,
		"external reference":    extRef,
		"neither some nor none": unhex(t, "02"),
		"no agent, then more":   unhex(t, "0000"),
	} {
		if a, ok, err := decodeAgent(b); err == nil {
			t.Errorf("%s: got %+v, %v and no error", name, a, ok)
		}
	}
}

func TestDecodeMetadata(t *testing.T) {
	v, ok, err := decodeMetadata(unhex(t, "01200000005b22021a5a27dc3a25d9cde2887e208f818b5a55dcfc6b2c3c0271634ab331c9"))
	if !ok || err != nil || len(v) != 32 || v[0] != 0x5b {
		t.Errorf("set: got %x, %v, %v", v, ok, err)
	}
	if _, ok, err := decodeMetadata(unhex(t, "00")); ok || err != nil {
		t.Errorf("unset: got %v, %v", ok, err)
	}
	for _, b := range []string{"", "0105000000aa", "0101000000aabb"} {
		if _, ok, err := decodeMetadata(unhex(t, b)); ok || err == nil {
			t.Errorf("%q: got %v, %v", b, ok, err)
		}
	}
}

// The events of a dry run of register on testnet, as 3dt3UMPz..., which
// would have minted agent 1167: CIS-2's mint, then the registry's own two.
var liveRegisterEvents = []string{
	"fe088f0400000000000001005b22021a5a27dc3a25d9cde2887e208f818b5a55dcfc6b2c3c0271634ab331c9",
	"f0088f040000000000005b22021a5a27dc3a25d9cde2887e208f818b5a55dcfc6b2c3c0271634ab331c9011d00000068747470733a2f2f6578616d706c652e6f72672f636172642e6a736f6e01abababababababababababababababababababababababababababababababab00fdc904d2a1010000",
	"f5088f04000000000000015b22021a5a27dc3a25d9cde2887e208f818b5a55dcfc6b2c3c0271634ab331c9fdc904d2a1010000",
}

func TestMintedTo(t *testing.T) {
	var events [][]byte
	for _, e := range liveRegisterEvents {
		events = append(events, unhex(t, e))
	}
	id, err := mintedTo(events, liveOwner)
	if err != nil || id != 1167 {
		t.Errorf("got %d, %v", id, err)
	}
	if _, err := mintedTo(events, "3whdieGHx43KKRwQYbC5pAUdmWZ61B7yreNRU9i36MtdCvajR8"); err == nil {
		t.Error("a mint to another account was taken for ours")
	}
	if _, err := mintedTo(append(events, events[0]), liveOwner); err == nil {
		t.Error("two mints were taken for one")
	}
	if _, err := mintedTo(nil, liveOwner); err == nil {
		t.Error("no mint was taken for one")
	}
}

func TestAddresses(t *testing.T) {
	testnet := networks["testnet"].Registry
	for id, want := range map[uint64]string{0: "JyP9TtQC3HCNrTYR3sc2T", 300: "JyP9UiZdQc2JZEnpqPnBz"} {
		if got := tokenAddress(testnet, id); got != want {
			t.Errorf("token %d: got %s, want %s", id, got, want)
		}
	}
	// Accounts, against the SDK's own encoding.
	sdk, err := v2.AccountAddressFromString(liveOwner)
	if err != nil {
		t.Fatal(err)
	}
	b, err := accountBytes(liveOwner)
	if err != nil || !bytes.Equal(b, sdk.Value[:]) || accountAddress(b) != sdk.ToBase58() {
		t.Errorf("got %x, %v", b, err)
	}
	broken := []byte(liveOwner)
	broken[10] = 'x'
	for _, s := range []string{string(broken), "JyP9TtQC3HCNrTYR3sc2T", "0OIl", ""} {
		if _, err := accountBytes(s); err == nil {
			t.Errorf("%q was taken for an account", s)
		}
	}
	// A payload starting with zero bytes keeps them, as leading 1s.
	if s := base58Check(0, []byte{0, 0, 1}); !strings.HasPrefix(s, "111") {
		t.Errorf("leading zeros: %s", s)
	}
	if b, err := base58CheckDecode(base58Check(0, []byte{0, 0, 1})); err != nil || !bytes.Equal(b, []byte{0, 0, 0, 1}) {
		t.Errorf("round trip with leading zeros: %x, %v", b, err)
	}
}

// otherAgent answers agentOf with another agent's record, as a node or
// contract that misbehaved might.
type otherAgent struct{ *fakeChain }

func (o otherAgent) view(ctx context.Context, ep string, p []byte) ([]byte, error) {
	if ep == "agentOf" {
		p = appendTokenID(nil, 7)
	}
	return o.fakeChain.view(ctx, ep, p)
}

func TestAgentMustBeTheOneAskedFor(t *testing.T) {
	f := newFakeChain(ownerAccount)
	f.agents[7] = &fakeAgent{owner: ownerAccount, meta: map[string][]byte{}}
	f.agents[8] = &fakeAgent{owner: otherAccount, meta: map[string][]byte{}}
	reg := registry{c: otherAgent{f}, net: networks["testnet"]}
	if _, _, err := reg.agent(context.Background(), 8); err == nil || !strings.Contains(err.Error(), "answered with agent 7") {
		t.Errorf("got %v", err)
	}
}

func writeAccount(t *testing.T, environment string, mode os.FileMode) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	export := map[string]any{
		"type": "concordium-browser-wallet-account", "v": 0, "environment": environment,
		"value": map[string]any{
			"accountKeys": map[string]any{
				"keys":      map[string]any{"0": map[string]any{"keys": map[string]any{"0": map[string]any{"signKey": hex.EncodeToString(priv.Seed()), "verifyKey": hex.EncodeToString(pub)}}, "threshold": 1}},
				"threshold": 1,
			},
			"address": ownerAccount,
		},
	}
	b, _ := json.Marshal(export)
	path := filepath.Join(t.TempDir(), "account.export")
	if err := os.WriteFile(path, b, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadAccount(t *testing.T) {
	var warned bytes.Buffer
	old := stderr
	stderr = &warned
	defer func() { stderr = old }()

	w, err := loadAccount(writeAccount(t, "testnet", 0o600), networks["testnet"])
	if err != nil || w.Address.ToBase58() != ownerAccount || w.NumberOfKeys() != 1 {
		t.Fatalf("got %v, %v", w, err)
	}
	if warned.Len() > 0 {
		t.Errorf("warned about a private key file: %s", warned.String())
	}
	if _, err := loadAccount(writeAccount(t, "testnet", 0o644), networks["testnet"]); err != nil || !strings.Contains(warned.String(), "can be read by others") {
		t.Errorf("a key file others can read: %v, warned %q", err, warned.String())
	}
	if _, err := loadAccount(writeAccount(t, "mainnet", 0o600), networks["testnet"]); err == nil || !strings.Contains(err.Error(), "is a mainnet account") {
		t.Errorf("a mainnet account on testnet: %v", err)
	}
	bad := filepath.Join(t.TempDir(), "bad")
	_ = os.WriteFile(bad, []byte(`{"value":{}}`), 0o600)
	if _, err := loadAccount(bad, networks["testnet"]); err == nil {
		t.Error("loaded a file with no account in it")
	}
}
