package main

import (
	"context"
	"errors"
	"fmt"
)

// chain is what the tool needs of a Concordium node: to call the registry
// without a transaction, and to send one. node.go implements it with
// Concordium's SDK; the tests use a fake registry.
type chain interface {
	// view calls a registry entrypoint as a query: nothing is sent or
	// paid for. It returns what the entrypoint returns.
	view(ctx context.Context, entrypoint string, param []byte) ([]byte, error)
	// update sends a transaction calling a registry entrypoint, signed by
	// the account, and waits until it's finalized. A transaction the
	// registry refused is an error, with its hash when it was sent.
	update(ctx context.Context, entrypoint string, param []byte) (txResult, error)
	// account is the account transactions are sent from, in base58, or ""
	// when no keys were given.
	account() string
}

// txResult is a finalized transaction.
type txResult struct {
	Hash   string   // hex
	Events [][]byte // the registry's contract events, in order
}

// rejectedError is a call the registry refused. Code is the contract's
// error code; the registry doesn't document them.
type rejectedError struct {
	Entrypoint string
	Code       int32
	TxHash     string // "" when it was refused in a dry run, before anything was sent
}

func (e *rejectedError) Error() string {
	where := "in a dry run, so nothing was sent"
	if e.TxHash != "" {
		where = "in transaction " + e.TxHash
	}
	return fmt.Sprintf("the registry refused %s with error %d, %s", e.Entrypoint, e.Code, where)
}

// errNoAccount means a transaction was asked for without keys.
var errNoAccount = errors.New("sending a transaction needs -account: the key file of the account that owns the agent")

// registry is the Agent Registry on one chain.
type registry struct {
	c   chain
	net network
}

// agent reads an agent's record. ok is false when there is no such agent.
func (r registry) agent(ctx context.Context, id uint64) (agentRecord, bool, error) {
	ret, err := r.c.view(ctx, "agentOf", appendTokenID(nil, id))
	if err != nil {
		return agentRecord{}, false, err
	}
	a, ok, err := decodeAgent(ret)
	if err == nil && ok && a.TokenID != id {
		return agentRecord{}, false, fmt.Errorf("asked for agent %d, the registry answered with agent %d", id, a.TokenID)
	}
	return a, ok, err
}

// metadata reads one key of an agent's on-chain store.
func (r registry) metadata(ctx context.Context, id uint64, key string) ([]byte, bool, error) {
	ret, err := r.c.view(ctx, "getMetadata", getMetadataParam(id, key))
	if err != nil {
		return nil, false, err
	}
	return decodeMetadata(ret)
}

// owned reads an agent and makes sure it's active and owned by the
// account transactions are sent from, so a transaction isn't sent, and
// paid for, only to be refused.
func (r registry) owned(ctx context.Context, id uint64) (agentRecord, error) {
	if r.c.account() == "" {
		return agentRecord{}, errNoAccount
	}
	a, ok, err := r.agent(ctx, id)
	switch {
	case err != nil:
		return a, err
	case !ok:
		return a, fmt.Errorf("there is no agent %d in the %s registry", id, r.net.Name)
	case !a.Active:
		return a, fmt.Errorf("agent %d was revoked", id)
	case a.Owner != r.c.account():
		return a, fmt.Errorf("agent %d is owned by %s, not by %s, whose keys were given", id, a.Owner, r.c.account())
	}
	return a, nil
}

// register mints a new agent to the account, with a card if uri is set.
// It returns the new agent's token ID, read from the finalized
// transaction.
func (r registry) register(ctx context.Context, uri string, cardHash *[32]byte) (uint64, txResult, error) {
	if r.c.account() == "" {
		return 0, txResult{}, errNoAccount
	}
	tx, err := r.c.update(ctx, "register", registerParam(uri, cardHash))
	if err != nil {
		return 0, tx, err
	}
	id, err := mintedTo(tx.Events, r.c.account())
	if err != nil {
		return 0, tx, fmt.Errorf("registered in transaction %s, but the new agent's ID couldn't be read from it: %w", tx.Hash, err)
	}
	return id, tx, nil
}
