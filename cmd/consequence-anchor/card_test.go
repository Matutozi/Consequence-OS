package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnchorValue(t *testing.T) {
	a := anchorValue{Seq: 1234567, Hash: "sha256:" + strings.Repeat("ab", 32), Head: "sha256:" + strings.Repeat("cd", 32)}
	b, err := encodeAnchor(a)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"hash":"sha256:` + strings.Repeat("ab", 32) + `","head":"sha256:` + strings.Repeat("cd", 32) + `","seq":1234567}`
	if string(b) != want {
		t.Errorf("got %s", b)
	}
	// It fits the registry with room to spare, even at the largest seq.
	big := a
	big.Seq = 1<<63 - 1
	if b, err := encodeAnchor(big); err != nil || len(b) > maxMetadataValue/2 {
		t.Errorf("the largest anchor is %d bytes: %v", len(b), err)
	}
	if got, err := decodeAnchor(b); err != nil || got != a {
		t.Errorf("round trip: %+v, %v", got, err)
	}

	for _, bad := range []anchorValue{
		{Seq: 0, Hash: a.Hash, Head: a.Head},
		{Seq: 1, Hash: "sha256:" + strings.Repeat("AB", 32), Head: a.Head},
		{Seq: 1, Hash: a.Hash, Head: "sha256:abc"},
		{Seq: 1, Hash: strings.Repeat("ab", 32), Head: a.Head},
	} {
		if _, err := encodeAnchor(bad); err == nil {
			t.Errorf("encoded %+v", bad)
		}
	}
	for _, bad := range []string{
		want[:len(want)-1] + `,"extra":1}`,
		want + `{}`,
		strings.Replace(want, `"seq":1234567`, `"seq":1,"seq":1234567`, 1), // a duplicate key, otherwise valid
		strings.Replace(want, `"seq":1234567`, `"seq":-1`, 1),
		strings.Replace(want, `"seq":1234567`, `"seq":"1234567"`, 1),
		`[]`, ``,
	} {
		if got, err := decodeAnchor([]byte(bad)); err == nil {
			t.Errorf("decoded %q as %+v", bad, got)
		}
	}
}

func TestBuildCard(t *testing.T) {
	id := uint64(300)
	in := cardInput{Name: "Refund bot", Description: "Issues refunds & credits", URL: "https://agents.example/refund.json",
		Owner: otherAccount, TokenID: &id, Issuer: "https://guard.example/", Net: networks["testnet"]}
	card, err := buildCard(in)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := buildCard(in)
	if !bytes.Equal(card, again) {
		t.Error("the same input gave two cards, so two hashes")
	}
	if bytes.Contains(card, []byte("\\u0026")) || !bytes.Contains(card, []byte("refunds & credits")) {
		t.Error("the card escapes & as \\u0026, which other builders don't")
	}

	g, ok, err := readGuard(card)
	if err != nil || !ok {
		t.Fatalf("readGuard: %v, %v", ok, err)
	}
	if g != (guardParams{Issuer: "https://guard.example", Keys: "https://guard.example/.well-known/consequence-keys", AnchorKey: anchorKey}) {
		t.Errorf("guard %+v", g)
	}

	// The badge block, as the registry's own builder wrote it for this
	// account on testnet (captured on 13 November 2026), with the token
	// address filled in.
	var c struct {
		URL          string `json:"url"`
		Capabilities struct {
			Extensions []struct {
				URI    string      `json:"uri"`
				Params badgeParams `json:"params"`
			} `json:"extensions"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(card, &c); err != nil {
		t.Fatal(err)
	}
	b := c.Capabilities.Extensions[0]
	const chain = "ccd:4221332d34e1694168c2a0c0b3fd0f27:"
	if b.URI != "https://docs.concordium.com/a2a-extensions/concordium-badge/v1" ||
		b.Params.Owner.Account != chain+otherAccount || b.Params.AgentWallet != chain+otherAccount ||
		b.Params.Contracts.CIS8004 != chain+"12802.0" || b.Params.Contracts.CIS8 != chain+"12801.0" ||
		b.Params.TokenAddress == nil || *b.Params.TokenAddress != "JyP9UiZdQc2JZEnpqPnBz" ||
		b.Params.Verification.VerifyURL != "https://agent-registry-mcp.concordium.com/v1/check-badge/JyP9UiZdQc2JZEnpqPnBz" {
		t.Errorf("badge block %+v", b)
	}
	if c.URL != in.URL {
		t.Errorf("url %q", c.URL)
	}

	// Before registering there's no token address yet.
	in.TokenID = nil
	pre, err := buildCard(in)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(pre, []byte(`"tokenAddress": null`)) {
		t.Errorf("a card before registering:\n%s", pre)
	}

	for name, change := range map[string]func(*cardInput){
		"no name":         func(c *cardInput) { c.Name = " " },
		"no desc":         func(c *cardInput) { c.Description = "" },
		"bad url":         func(c *cardInput) { c.URL = "agents.example/refund.json" },
		"ftp url":         func(c *cardInput) { c.URL = "ftp://agents.example/c" },
		"bad issuer":      func(c *cardInput) { c.Issuer = "" },
		"bad owner":       func(c *cardInput) { c.Owner = "JyP9UiZdQc2JZEnpqPnBz" },
		"no owner at all": func(c *cardInput) { c.Owner = "" },
	} {
		bad := in
		change(&bad)
		if _, err := buildCard(bad); err == nil {
			t.Errorf("%s: built a card", name)
		}
	}
}

func TestReadGuard(t *testing.T) {
	ext := `{"uri":"` + guardExtensionURI + `","description":"","required":false,"params":{"issuer":"https://g","keys":"https://g/k","anchorKey":"k"}}`
	for name, tc := range map[string]struct {
		card   string
		ok     bool
		errors bool
	}{
		"none":          {`{"capabilities":{"extensions":[]}}`, false, false},
		"no caps":       {`{}`, false, false},
		"one":           {`{"capabilities":{"extensions":[` + ext + `]}}`, true, false},
		"twice":         {`{"capabilities":{"extensions":[` + ext + `,` + ext + `]}}`, false, true},
		"unknown param": {`{"capabilities":{"extensions":[` + strings.Replace(ext, `"anchorKey"`, `"extra":1,"anchorKey"`, 1) + `]}}`, false, true},
		"missing keys":  {`{"capabilities":{"extensions":[` + strings.Replace(ext, `"https://g/k"`, `""`, 1) + `]}}`, false, true},
		"not json":      {`{`, false, true},
	} {
		_, ok, err := readGuard([]byte(tc.card))
		if ok != tc.ok || (err != nil) != tc.errors {
			t.Errorf("%s: got %v, %v", name, ok, err)
		}
	}
}

func TestRunFlags(t *testing.T) {
	dialed := false
	old := dial
	dial = func(ctx context.Context, net network, addr string, plaintext bool, accountFile string) (chain, func(), error) {
		dialed = true
		return newFakeChain(ownerAccount), func() {}, nil
	}
	defer func() { dial = old }()
	t.Setenv("CONSEQUENCE_ADMIN_TOKEN", "")

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"frobnicate"}, "unknown command"},
		{[]string{"verify"}, "needs -token"},
		{[]string{"verify", "-token", "x"}, "a whole number"},
		{[]string{"verify", "-token", "1", "extra"}, "takes flags only"},
		{[]string{"verify", "-token", "1", "-network", "devnet"}, "testnet or mainnet"},
		{[]string{"verify", "-token", "1", "-plaintext"}, "give its address with -node"},
		{[]string{"register"}, "needs -account"},
		{[]string{"set-card", "-token", "1"}, "needs -account"},
		{[]string{"anchor", "-token", "1", "-account", "k"}, "needs -server"},
		{[]string{"anchor", "-token", "1", "-account", "k", "-server", "https://g"}, "$CONSEQUENCE_ADMIN_TOKEN, which is empty"},
		{[]string{"card", "-url", "https://x/c"}, "needs -url"},
		{[]string{"card", "-url", "https://x/c", "-server", "https://g"}, "-account KEYS or -owner ACCOUNT"},
	} {
		dialed = false
		err := run(context.Background(), tc.args, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: got %v, want %q", tc.args, err, tc.want)
		}
		if dialed {
			t.Errorf("%v: reached the node before the flags checked out", tc.args)
		}
	}

	// card writes a file, without a node.
	out := filepath.Join(t.TempDir(), "card.json")
	var buf bytes.Buffer
	err := run(context.Background(), []string{"card", "-token", "5", "-url", "https://agents.example/c.json", "-name", "Bot", "-description", "Does things",
		"-server", "https://guard.example", "-owner", ownerAccount, "-out", out}, &buf)
	if err != nil || dialed {
		t.Fatalf("card: %v, dialed %v", err, dialed)
	}
	card, _ := os.ReadFile(out)
	if _, ok, _ := readGuard(card); !ok || !strings.Contains(buf.String(), "set-card -token 5 -url https://agents.example/c.json") {
		t.Errorf("card wrote %s and said\n%s", card, buf.String())
	}

	// verify reads the chain without keys, even when -account is given.
	var gotAccount string
	dial = func(ctx context.Context, net network, addr string, plaintext bool, accountFile string) (chain, func(), error) {
		gotAccount = accountFile
		return newFakeChain(""), func() {}, nil
	}
	if err := run(context.Background(), []string{"verify", "-token", "1", "-account", "keys.json"}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "no agent 1") {
		t.Errorf("verify: %v", err)
	}
	if gotAccount != "" {
		t.Error("verify loaded the account's keys")
	}
	if err := run(context.Background(), nil, &buf); err != nil || !strings.Contains(buf.String(), "usage:") {
		t.Errorf("no command: %v", err)
	}
}
