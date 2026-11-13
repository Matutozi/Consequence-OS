package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/matutozi/consequence-os/pkg/verify"
)

// tool runs the commands, over a registry and a ConsequenceOS server.
type tool struct {
	reg  registry
	srv  guardServer
	http *http.Client // for cards and keys
	out  io.Writer
}

// refusal is anchoring refused because the audit log doesn't hold up:
// what anchoring exists to catch. anchor -every stops on it, where it
// carries on after a network error.
type refusal struct{ why string }

func (r *refusal) Error() string { return r.why }

// fetchCard reads a card from its URL and checks it against the SHA-256
// the registry pinned, if one is given.
func (t tool) fetchCard(ctx context.Context, uri string, pinned *[32]byte) ([]byte, error) {
	card, err := fetchURL(ctx, t.http, uri)
	if err != nil {
		return nil, fmt.Errorf("fetch the agent's card: %w", err)
	}
	if pinned != nil && sha256.Sum256(card) != *pinned {
		return card, fmt.Errorf("the card at %s isn't the one the registry pinned: its SHA-256 is %x, the registry's %x", uri, sha256.Sum256(card), *pinned)
	}
	return card, nil
}

// guardedCard fetches a card that is about to be pinned and makes sure it
// says the agent is guarded, since verify reads the keys and the anchor's
// key from it.
func (t tool) guardedCard(ctx context.Context, uri string) ([]byte, [32]byte, error) {
	card, err := t.fetchCard(ctx, uri, nil)
	if err != nil {
		return nil, [32]byte{}, err
	}
	if _, ok, err := readGuard(card); err != nil {
		return nil, [32]byte{}, err
	} else if !ok {
		return nil, [32]byte{}, fmt.Errorf("the card at %s doesn't say the agent is guarded by ConsequenceOS; make one with consequence-anchor card", uri)
	}
	return card, sha256.Sum256(card), nil
}

// register mints a new agent, with a card when cardURL is set.
func (t tool) register(ctx context.Context, cardURL string) error {
	var pinned *[32]byte
	if cardURL != "" {
		_, sum, err := t.guardedCard(ctx, cardURL)
		if err != nil {
			return err
		}
		pinned = &sum
	}
	id, tx, err := t.reg.register(ctx, cardURL, pinned)
	if err != nil {
		return err
	}
	fmt.Fprintf(t.out, "Registered agent %d on %s, owned by %s.\n  badge:       %s\n  transaction: %s\n",
		id, t.reg.net.Name, t.reg.c.account(), tokenAddress(t.reg.net.Registry, id), t.reg.net.txLink(tx.Hash))
	if cardURL == "" {
		fmt.Fprintf(t.out, "Next: write its card with consequence-anchor card -token %d, host it, and pin it with consequence-anchor set-card.\n", id)
	} else {
		fmt.Fprintf(t.out, "Its card at %s is pinned. Next: consequence-anchor anchor -token %d.\n", cardURL, id)
	}
	return nil
}

// card writes an agent's card to file.
func (t tool) card(in cardInput, file string) error {
	card, err := buildCard(in)
	if err != nil {
		return err
	}
	if err := os.WriteFile(file, card, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(t.out, "Wrote the card to %s (SHA-256 %x).\n", file, sha256.Sum256(card))
	fmt.Fprintf(t.out, "Host it unchanged at %s: the registry pins its exact bytes.\n", in.URL)
	if in.TokenID != nil {
		fmt.Fprintf(t.out, "Then: consequence-anchor set-card -token %d -url %s\n", *in.TokenID, in.URL)
	} else {
		fmt.Fprintf(t.out, "Then: consequence-anchor register -card-url %s\n", in.URL)
	}
	return nil
}

// setCard pins the card at uri to agent id. When file is set, the URL
// must serve exactly that file.
func (t tool) setCard(ctx context.Context, id uint64, uri, file string) error {
	if _, err := t.reg.owned(ctx, id); err != nil {
		return err
	}
	card, sum, err := t.guardedCard(ctx, uri)
	if err != nil {
		return err
	}
	if file != "" {
		local, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		if !bytes.Equal(local, card) {
			return fmt.Errorf("%s serves something other than %s; host the file unchanged", uri, file)
		}
	}
	tx, err := t.reg.c.update(ctx, "setAgentURI", setAgentURIParam(id, uri, sum))
	if err != nil {
		return err
	}
	fmt.Fprintf(t.out, "Pinned the card at %s (SHA-256 %x) to agent %d.\n  transaction: %s\n", uri, sum, id, t.reg.net.txLink(tx.Hash))
	return nil
}

// anchor anchors the server's current audit head in agent id's registry
// record, after checking that the log still holds the head anchored last.
// It returns whether a transaction was sent.
func (t tool) anchor(ctx context.Context, id uint64, headsDir string) (bool, error) {
	agent, err := t.reg.owned(ctx, id)
	if err != nil {
		return false, err
	}
	var guard *guardParams
	if agent.CardURI != "" {
		card, err := t.fetchCard(ctx, agent.CardURI, agent.CardHash)
		if err != nil {
			return false, err
		}
		if g, ok, err := readGuard(card); err != nil {
			return false, err
		} else if ok {
			guard = &g
		}
	}
	if guard == nil {
		fmt.Fprintf(stderr, "warning: agent %d's card doesn't say it's guarded by ConsequenceOS, so verifiers won't find the keys to check its heads with; see consequence-anchor card\n", id)
	} else if guard.AnchorKey != anchorKey {
		return false, fmt.Errorf("agent %d's card says its head is anchored under %q; this tool anchors under %q", id, guard.AnchorKey, anchorKey)
	}

	var held *anchorValue
	raw, ok, err := t.reg.metadata(ctx, id, anchorKey)
	if err != nil {
		return false, err
	}
	if ok {
		a, err := decodeAnchor(raw)
		if err != nil {
			return false, fmt.Errorf("agent %d's %s isn't an anchor this tool wrote (%w); nothing was anchored", id, anchorKey, err)
		}
		held = &a
	}

	// Ask the server to check its log, holding it to the anchored head:
	// anchoring a newer head over a log that was cut back or rebuilt would
	// vouch for the rewrite.
	rep, err := t.srv.verifyChain(ctx, held)
	if err != nil {
		return false, err
	}
	if !rep.Intact {
		where := ""
		if rep.BrokenAt != "" {
			where = " at entry " + rep.BrokenAt
		}
		kept := "Nothing was anchored."
		if held != nil {
			kept = fmt.Sprintf("Nothing was anchored: the anchor on-chain, entry %d (%s), stays as evidence of the log before.", held.Seq, held.Hash)
		}
		return false, &refusal{fmt.Sprintf("the audit log doesn't hold up%s: %s. %s", where, rep.Problem, kept)}
	}

	signed, err := t.srv.head(ctx)
	if err != nil {
		return false, err
	}
	keys, err := t.srv.keys(ctx)
	if err != nil {
		return false, err
	}
	head, err := verify.VerifyAuditHead(signed, keys)
	if err != nil {
		return false, fmt.Errorf("the server's signed head doesn't check out with its own keys: %w", err)
	}
	if guard != nil && head.Issuer != guard.Issuer {
		return false, fmt.Errorf("agent %d's card says it's guarded by %s, but this server signs as %s; anchor the right server's log", id, guard.Issuer, head.Issuer)
	}
	switch {
	case head.Seq < rep.HeadSeq:
		return false, &refusal{fmt.Sprintf("the server's head is entry %d, behind the %d it had just checked: the log went back. Nothing was anchored", head.Seq, rep.HeadSeq)}
	case held == nil:
	case head.Seq < held.Seq:
		return false, &refusal{fmt.Sprintf("the server's head is entry %d, before the anchored entry %d: the log went back. Nothing was anchored", head.Seq, held.Seq)}
	case head.Seq == held.Seq && head.Hash != held.Hash:
		return false, &refusal{fmt.Sprintf("the server's head is entry %d with hash %s, and the anchor says %s: the log was rewritten. Nothing was anchored", head.Seq, head.Hash, held.Hash)}
	case head.Seq == held.Seq:
		fmt.Fprintf(t.out, "Entry %d is already anchored; nothing new to anchor, nothing sent.\n", head.Seq)
		return false, nil
	}

	value, err := encodeAnchor(anchorValue{Hash: head.Hash, Head: digest(signed), Seq: head.Seq})
	if err != nil {
		return false, err
	}
	param, err := setMetadataParam(id, anchorKey, value)
	if err != nil {
		return false, err
	}
	// The signed head is kept before the anchor is sent, so an anchor
	// on-chain always has its head on disk.
	saved, err := saveHead(headsDir, head.Seq, signed)
	if err != nil {
		return false, err
	}
	tx, err := t.reg.c.update(ctx, "setMetadata", param)
	if err != nil {
		return false, err
	}
	fmt.Fprintf(t.out, "Anchored entry %d of %s's audit log in agent %d's registry record.\n  anchor:      %s\n  transaction: %s\n  signed head: %s\n",
		head.Seq, head.Issuer, id, value, t.reg.net.txLink(tx.Hash), saved)
	return true, nil
}

// saveHead keeps a signed head as dir/head-<seq>.json, never overwriting a
// different one.
func saveHead(dir string, seq int64, signed []byte) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, fmt.Sprintf("head-%d.json", seq))
	if old, err := os.ReadFile(path); err == nil {
		if bytes.Equal(old, signed) {
			return path, nil
		}
		return "", fmt.Errorf("%s already holds a different head for entry %d; it's kept, and nothing was anchored", path, seq)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "", err
	}
	if _, err := f.Write(signed); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return "", err
	}
	return path, f.Close()
}

// anchorEvery anchors now and then every interval, until ctx ends or the
// log doesn't hold up. A network error is reported and tried again at the
// next interval; a refusal stops it, since it means the log was changed.
func (t tool) anchorEvery(ctx context.Context, id uint64, headsDir string, every time.Duration) error {
	for {
		_, err := t.anchor(ctx, id, headsDir)
		var r *refusal
		switch {
		case errors.As(err, &r):
			return err
		case err != nil && ctx.Err() == nil:
			fmt.Fprintf(stderr, "%s: anchoring failed, trying again in %s: %v\n", time.Now().Format(time.RFC3339), every, err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(every):
		}
	}
}

// verifyAgent checks, from the chain alone, what an agent's record says,
// and that headFile, when given, is the anchored head and is signed by the
// keys the card names (or keysURL). It prints what it found and returns
// an error if anything doesn't hold up.
func (t tool) verifyAgent(ctx context.Context, id uint64, headFile, keysURL string) error {
	a, ok, err := t.reg.agent(ctx, id)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("there is no agent %d in the %s registry", id, t.reg.net.Name)
	}
	var problems []string
	status := "active"
	if !a.Active {
		status = "REVOKED"
		problems = append(problems, "the agent was revoked")
	}
	fmt.Fprintf(t.out, "agent %d on %s, badge %s\n  owner:  %s\n  status: %s\n", id, t.reg.net.Name, tokenAddress(t.reg.net.Registry, id), a.Owner, status)

	var guard *guardParams
	switch {
	case a.CardURI == "":
		fmt.Fprintln(t.out, "  card:   none")
		problems = append(problems, "the agent has no card, so nothing says it's guarded or where its keys are")
	case a.CardHash == nil:
		fmt.Fprintf(t.out, "  card:   %s, NOT PINNED\n", a.CardURI)
		problems = append(problems, "the registry holds no SHA-256 for the card, so whoever serves it can change it")
	default:
		card, err := t.fetchCard(ctx, a.CardURI, a.CardHash)
		if err != nil {
			state := "DOESN'T MATCH"
			if card == nil {
				state = "COULDN'T BE FETCHED"
			}
			fmt.Fprintf(t.out, "  card:   %s, %s\n", a.CardURI, state)
			problems = append(problems, err.Error())
			break
		}
		fmt.Fprintf(t.out, "  card:   %s, matches the SHA-256 the registry pinned\n", a.CardURI)
		g, ok, err := readGuard(card)
		switch {
		case err != nil:
			problems = append(problems, err.Error())
		case !ok:
			problems = append(problems, "the card doesn't say the agent is guarded by ConsequenceOS")
		default:
			guard = &g
			fmt.Fprintf(t.out, "  guard:  ConsequenceOS at %s, keys at %s\n", g.Issuer, g.Keys)
		}
	}

	key := anchorKey
	if guard != nil {
		key = guard.AnchorKey
	}
	raw, ok, err := t.reg.metadata(ctx, id, key)
	if err != nil {
		return err
	}
	var anchored *anchorValue
	switch {
	case !ok:
		fmt.Fprintln(t.out, "  anchor: none")
		problems = append(problems, "nothing is anchored under "+key)
	default:
		a, err := decodeAnchor(raw)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s holds something that isn't an anchor: %v", key, err))
			break
		}
		anchored = &a
		fmt.Fprintf(t.out, "  anchor: entry %d, %s\n          signed head %s\n", a.Seq, a.Hash, a.Head)
	}

	if anchored != nil && headFile == "" {
		fmt.Fprintln(t.out, "Give -head with the signed head saved when it was anchored, to check its signatures.")
	}
	if anchored != nil && headFile != "" {
		problems = append(problems, t.checkHeadFile(ctx, *anchored, guard, headFile, keysURL)...)
	}

	if len(problems) > 0 {
		for _, p := range problems {
			fmt.Fprintf(t.out, "PROBLEM: %s\n", p)
		}
		return errors.New("the agent's record doesn't check out")
	}
	fmt.Fprintln(t.out, "ok")
	return nil
}

// checkHeadFile checks a saved signed head against the anchor.
func (t tool) checkHeadFile(ctx context.Context, anchored anchorValue, guard *guardParams, headFile, keysURL string) []string {
	signed, err := os.ReadFile(headFile)
	if err != nil {
		return []string{err.Error()}
	}
	if d := digest(signed); d != anchored.Head {
		return []string{fmt.Sprintf("%s isn't the anchored head: its SHA-256 is %s", headFile, d)}
	}
	if keysURL == "" && guard != nil {
		keysURL = guard.Keys
	}
	if keysURL == "" {
		return []string{"no keys to check the head's signatures with: the card names none, so give -keys"}
	}
	keys, err := keysAt(ctx, t.http, keysURL)
	if err != nil {
		return []string{fmt.Sprintf("read the keys at %s: %v", keysURL, err)}
	}
	head, err := verify.VerifyAuditHead(signed, keys)
	if err != nil {
		return []string{fmt.Sprintf("%s doesn't verify with the keys at %s: %v", headFile, keysURL, err)}
	}
	var problems []string
	if head.Seq != anchored.Seq || head.Hash != anchored.Hash {
		problems = append(problems, fmt.Sprintf("%s names entry %d (%s), the anchor entry %d (%s)", headFile, head.Seq, head.Hash, anchored.Seq, anchored.Hash))
	}
	if guard != nil && head.Issuer != guard.Issuer {
		problems = append(problems, fmt.Sprintf("%s was signed by %s, and the card names %s", headFile, head.Issuer, guard.Issuer))
	}
	if len(problems) == 0 {
		fmt.Fprintf(t.out, "  head:   %s is the anchored head, signed by %s at %s\n", headFile, head.Issuer, head.SignedAt.UTC().Format(time.RFC3339))
		fmt.Fprintf(t.out, "Next, with the server's config: consequenced -verify-audit -audit-head %s checks the log still contains it.\n", shellQuote(headFile))
	}
	return problems
}

func shellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
