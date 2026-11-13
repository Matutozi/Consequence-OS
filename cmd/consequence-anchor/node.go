package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	v2 "github.com/Concordium/concordium-go-sdk/v2"
	"github.com/Concordium/concordium-go-sdk/v2/pb"
	"github.com/Concordium/concordium-go-sdk/v2/transactions/send"
	"google.golang.org/grpc/credentials"
)

// node is a chain reached through a Concordium node's gRPC API, with
// Concordium's Go SDK.
type node struct {
	client *v2.Client
	net    network
	wallet *v2.WalletAccount // nil: queries only
	// wait bounds how long update waits for a transaction to be finalized.
	wait time.Duration
}

// dialNode connects to addr and checks it is on net's chain: a node on
// another chain would read another registry, or spend real CCD where test
// CCD was meant.
func dialNode(ctx context.Context, net network, addr string, plaintext bool, wallet *v2.WalletAccount) (*node, error) {
	cfg := v2.Config{NodeAddress: addr}
	if !plaintext {
		cfg.TlsCredentials = credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	}
	client, err := v2.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("connect to the node at %s: %w", addr, err)
	}
	info, err := client.GetConsensusInfo(ctx)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("ask the node at %s which chain it's on: %w", addr, err)
	}
	if g := info.GetGenesisBlock().GetValue(); len(g) < 16 || hex.EncodeToString(g[:16]) != net.Genesis {
		client.Close()
		return nil, fmt.Errorf("the node at %s isn't on %s (its genesis block is %x); give -node a %s node", addr, net.Name, g, net.Name)
	}
	return &node{client: client, net: net, wallet: wallet, wait: 3 * time.Minute}, nil
}

func (n *node) Close() error { return n.client.Close() }

func (n *node) account() string {
	if n.wallet == nil {
		return ""
	}
	return n.wallet.Address.ToBase58()
}

func (n *node) payload(entrypoint string, param []byte) v2.UpdateContractPayload {
	return v2.UpdateContractPayload{
		Amount:      &v2.Amount{},
		Address:     &v2.ContractAddress{Index: n.net.Registry.Index, Subindex: n.net.Registry.Subindex},
		ReceiveName: &v2.ReceiveName{Value: "CIS-8004." + entrypoint},
		Parameter:   &v2.Parameter{Value: param},
	}
}

// queryEnergy bounds a query's work. The registry's calls use a few
// thousand; this is room to spare, and costs nothing.
const queryEnergy = 1_000_000

// invoke runs entrypoint on the last finalized block, as the account when
// there is one, so a dry run sees what the transaction would.
func (n *node) invoke(ctx context.Context, entrypoint string, param []byte) (*pb.InvokeInstanceResponse_Success, error) {
	var res *pb.InvokeInstanceResponse
	var err error
	if n.wallet != nil {
		res, err = n.client.InvokeInstance(ctx, n.payload(entrypoint, param), v2.BlockHashInputLastFinal{}, v2.Energy{Value: queryEnergy}, n.wallet.Address)
	} else {
		self := &v2.ContractAddress{Index: n.net.Registry.Index, Subindex: n.net.Registry.Subindex}
		res, err = n.client.InvokeInstance(ctx, n.payload(entrypoint, param), v2.BlockHashInputLastFinal{}, v2.Energy{Value: queryEnergy}, self)
	}
	if err != nil {
		return nil, fmt.Errorf("call the registry's %s: %w", entrypoint, err)
	}
	if s := res.GetSuccess(); s != nil {
		return s, nil
	}
	if r := res.GetFailure().GetReason().GetRejectedReceive(); r != nil {
		return nil, &rejectedError{Entrypoint: entrypoint, Code: r.GetRejectReason()}
	}
	return nil, fmt.Errorf("the registry's %s failed: %v", entrypoint, res.GetFailure().GetReason())
}

func (n *node) view(ctx context.Context, entrypoint string, param []byte) ([]byte, error) {
	s, err := n.invoke(ctx, entrypoint, param)
	if err != nil {
		return nil, err
	}
	return s.GetReturnValue(), nil
}

// update dry-runs the call first: a call the registry would refuse isn't
// sent, so it costs nothing, and the dry run gives the energy to allow.
// Concordium charges for the energy used, not the energy allowed.
func (n *node) update(ctx context.Context, entrypoint string, param []byte) (txResult, error) {
	if n.wallet == nil {
		return txResult{}, errNoAccount
	}
	dry, err := n.invoke(ctx, entrypoint, param)
	if err != nil {
		return txResult{}, err
	}
	used := dry.GetUsedEnergy().GetValue()
	energy := v2.Energy{Value: used + used/2 + 500}

	seq, err := n.client.GetNextAccountSequenceNumber(ctx, n.wallet.Address)
	if err != nil {
		return txResult{}, fmt.Errorf("read the account's next transaction number: %w", err)
	}
	expiry := v2.TransactionTime{Value: uint64(time.Now().Add(5 * time.Minute).Unix())}
	tx, err := send.UpdateContract(n.wallet, *n.wallet.Address, v2.SequenceNumber{Value: seq.GetSequenceNumber().GetValue()}, expiry, n.payload(entrypoint, param), energy)
	if err != nil {
		return txResult{}, fmt.Errorf("sign the transaction: %w", err)
	}
	hash, err := tx.Send(ctx, n.client)
	if err != nil {
		return txResult{}, fmt.Errorf("send the transaction: %w", err)
	}
	return n.finalized(ctx, entrypoint, *hash)
}

// finalized waits for the transaction to be finalized and reads what the
// registry did.
func (n *node) finalized(ctx context.Context, entrypoint string, h v2.TransactionHash) (txResult, error) {
	hash := h.Hex()
	res := txResult{Hash: hash}
	ctx, cancel := context.WithTimeout(ctx, n.wait)
	defer cancel()
	for {
		status, err := n.client.GetBlockItemStatus(ctx, h)
		if err == nil {
			if f := status.GetFinalized(); f != nil {
				return n.outcome(res, entrypoint, f.GetOutcome().GetOutcome())
			}
		}
		select {
		case <-ctx.Done():
			return res, fmt.Errorf("transaction %s was sent, but wasn't finalized within %s; look it up on %s", hash, n.wait, n.net.txLink(hash))
		case <-time.After(2 * time.Second):
		}
	}
}

func (n *node) outcome(res txResult, entrypoint string, summary *pb.BlockItemSummary) (txResult, error) {
	effects := summary.GetAccountTransaction().GetEffects()
	if none := effects.GetNone(); none != nil {
		if r := none.GetRejectReason().GetRejectedReceive(); r != nil {
			return res, &rejectedError{Entrypoint: entrypoint, Code: r.GetRejectReason(), TxHash: res.Hash}
		}
		return res, fmt.Errorf("transaction %s was rejected: %v", res.Hash, none.GetRejectReason())
	}
	update := effects.GetContractUpdateIssued()
	if update == nil {
		return res, fmt.Errorf("transaction %s didn't update the registry", res.Hash)
	}
	for _, e := range update.GetEffects() {
		u := e.GetUpdated()
		if u == nil || u.GetAddress().GetIndex() != n.net.Registry.Index || u.GetAddress().GetSubindex() != n.net.Registry.Subindex {
			continue
		}
		for _, ev := range u.GetEvents() {
			res.Events = append(res.Events, ev.GetValue())
		}
	}
	return res, nil
}

// loadAccount reads an account's key file, as Concordium's wallets export
// it. Its keys sign every transaction the tool sends, so the file should
// be readable by its owner alone.
func loadAccount(path string, net network) (*v2.WalletAccount, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(stderr, "warning: %s, which holds the account's signing keys, can be read by others; chmod 600 it\n", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// The browser wallet's export says which network the account is on.
	var meta struct {
		Environment string `json:"environment"`
	}
	if json.Unmarshal(data, &meta) == nil && meta.Environment != "" && meta.Environment != net.Name {
		return nil, fmt.Errorf("%s is a %s account, and this is %s; pick the network with -network", path, meta.Environment, net.Name)
	}
	w, err := v2.NewWalletAccountFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s isn't an account key file as Concordium's wallets export them: %w", path, err)
	}
	if w.NumberOfKeys() == 0 {
		return nil, errors.New(path + " has no signing keys")
	}
	return w, nil
}
