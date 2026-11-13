// Command consequence-anchor gives an agent guarded by ConsequenceOS an
// identity in Concordium's Agent Registry, and anchors the head of its
// audit log there, so anyone can later check the log wasn't rewritten.
//
//	consequence-anchor register -account KEYS [-card-url URL]
//	    mint the agent in the registry, owned by the account in KEYS
//	consequence-anchor card -token N -url URL -name NAME -description TEXT -server URL (-account KEYS | -owner ACCOUNT) [-out FILE]
//	    write the agent's card: the Concordium badge, and ConsequenceOS's
//	    extension naming the guard, its keys and where the head is anchored
//	consequence-anchor set-card -account KEYS -token N -url URL [-file FILE]
//	    pin the card hosted at URL to the agent (its URL and SHA-256)
//	consequence-anchor anchor -account KEYS -token N -server URL [-heads DIR] [-every 1h]
//	    check the server's log still holds the head anchored last, then
//	    anchor its current signed head in the agent's registry record
//	consequence-anchor verify -token N [-head FILE] [-keys URL]
//	    check the agent's record from the chain: active, its card matches,
//	    and what's anchored; with -head, that FILE is the anchored head and
//	    is signed by the keys the card names
//
// Every command takes -network (testnet, the default, or mainnet), and
// -node to use another node than Concordium's public one. KEYS is the
// account's key file, as Concordium's wallets export it. The admin token
// for -server is read from $CONSEQUENCE_ADMIN_TOKEN (-admin-token-env
// names another variable).
//
// See docs/concordium.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

var stderr io.Writer = os.Stderr

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(stderr, "consequence-anchor:", err)
		os.Exit(1)
	}
}

const usage = `usage: consequence-anchor COMMAND [flags]

  register   mint the agent in Concordium's Agent Registry
  card       write the agent's card, to host and pin
  set-card   pin a hosted card to the agent
  anchor     anchor the audit log's signed head in the agent's record
  verify     check the agent's record and what's anchored, from the chain

consequence-anchor COMMAND -h lists a command's flags. See docs/concordium.md.`

// dial connects to the network's node; it is replaced in tests.
var dial = func(ctx context.Context, net network, addr string, plaintext bool, accountFile string) (chain, func(), error) {
	var n *node
	var err error
	if accountFile == "" {
		n, err = dialNode(ctx, net, addr, plaintext, nil)
	} else {
		w, werr := loadAccount(accountFile, net)
		if werr != nil {
			return nil, nil, werr
		}
		n, err = dialNode(ctx, net, addr, plaintext, w)
	}
	if err != nil {
		return nil, nil, err
	}
	return n, func() { n.Close() }, nil
}

func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "-help" || args[0] == "help" {
		fmt.Fprintln(out, usage)
		return nil
	}
	cmd := args[0]
	fs := flag.NewFlagSet("consequence-anchor "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	netName := fs.String("network", "testnet", "the Concordium network: testnet or mainnet")
	nodeAddr := fs.String("node", "", "a node's gRPC address, host:port (default: Concordium's public node for -network)")
	plaintext := fs.Bool("plaintext", false, "talk to -node without TLS, as to a node of your own on localhost")
	account := fs.String("account", "", "the key file of the account that owns the agent, as Concordium's wallets export it")
	var token *string
	var server, tokenEnv *string
	if cmd != "register" {
		token = fs.String("token", "", "the agent's token ID in the registry, as register printed it")
	}
	if cmd == "anchor" || cmd == "card" {
		server = fs.String("server", "", "the ConsequenceOS server's public URL")
	}
	if cmd == "anchor" {
		tokenEnv = fs.String("admin-token-env", "CONSEQUENCE_ADMIN_TOKEN", "the environment variable holding the server's admin token")
	}
	var cardURL, name, description, owner, outFile, file, headsDir, headFile, keysURL *string
	var every *time.Duration
	switch cmd {
	case "register":
		cardURL = fs.String("card-url", "", "a card already hosted, made with consequence-anchor card, to pin as the agent registers")
	case "card":
		cardURL = fs.String("url", "", "where the card will be hosted")
		name = fs.String("name", "", "the agent's name")
		description = fs.String("description", "", "what the agent does")
		owner = fs.String("owner", "", "the owning account, when -account isn't given")
		outFile = fs.String("out", "agent-card.json", "where to write the card")
	case "set-card":
		cardURL = fs.String("url", "", "where the card is hosted")
		file = fs.String("file", "", "the card file, to check the URL serves it unchanged")
	case "anchor":
		headsDir = fs.String("heads", "anchored-heads", "where to keep each signed head anchored, as head-SEQ.json")
		every = fs.Duration("every", 0, "keep running, anchoring this often (e.g. 1h); 0 anchors once")
	case "verify":
		headFile = fs.String("head", "", "the signed head saved when it was anchored, to check against the anchor and its keys")
		keysURL = fs.String("keys", "", "the URL of the guard's public keys (default: the one the card names)")
	default:
		return fmt.Errorf("unknown command %q\n\n%s", cmd, usage)
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("%s takes flags only, not %q", cmd, fs.Args())
	}

	net, ok := networks[*netName]
	if !ok {
		return fmt.Errorf("-network is testnet or mainnet, not %q", *netName)
	}
	addr := *nodeAddr
	if addr == "" {
		if *plaintext {
			return errors.New("-plaintext is for a node of your own; give its address with -node")
		}
		addr = net.Node
	}
	var id uint64
	if token != nil && *token == "" && cmd != "card" {
		return fmt.Errorf("%s needs -token: the agent's token ID, as register printed it", cmd)
	}
	if token != nil && *token != "" {
		v, err := strconv.ParseUint(*token, 10, 64)
		if err != nil {
			return fmt.Errorf("-token is the agent's token ID, a whole number, not %q", *token)
		}
		id = v
	}

	t := tool{http: &http.Client{Timeout: 30 * time.Second}, out: out}

	// card needs no node: it writes a file.
	if cmd == "card" {
		if *cardURL == "" || *server == "" {
			return errors.New("card needs -url, where the card will be hosted, and -server, the ConsequenceOS server's public URL")
		}
		ownerAddr := *owner
		if *account != "" {
			w, err := loadAccount(*account, net)
			if err != nil {
				return err
			}
			ownerAddr = w.Address.ToBase58()
		}
		if ownerAddr == "" {
			return errors.New("card needs the owning account: -account KEYS or -owner ACCOUNT")
		}
		var tokenID *uint64
		if *token != "" {
			tokenID = &id
		}
		return t.card(cardInput{Name: *name, Description: *description, URL: *cardURL, Owner: ownerAddr, TokenID: tokenID, Issuer: *server, Net: net}, *outFile)
	}

	if cmd == "anchor" {
		if *server == "" {
			return errors.New("anchor needs -server: the ConsequenceOS server's public URL")
		}
		t.srv = guardServer{base: *server, token: os.Getenv(*tokenEnv), http: t.http}
		if t.srv.token == "" {
			return fmt.Errorf("anchor reads the server's admin token from $%s, which is empty", *tokenEnv)
		}
	}
	needsKeys := cmd == "register" || cmd == "set-card" || cmd == "anchor"
	if needsKeys && *account == "" {
		return fmt.Errorf("%s sends a transaction, so it needs -account: the key file of the account that owns the agent", cmd)
	}
	accountFile := *account
	if !needsKeys {
		accountFile = "" // verify reads the chain only, as anyone can
	}
	c, closeNode, err := dial(ctx, net, addr, *plaintext, accountFile)
	if err != nil {
		return err
	}
	defer closeNode()
	t.reg = registry{c: c, net: net}

	switch cmd {
	case "register":
		return t.register(ctx, *cardURL)
	case "set-card":
		if *cardURL == "" {
			return errors.New("set-card needs -url: where the card is hosted")
		}
		return t.setCard(ctx, id, *cardURL, *file)
	case "anchor":
		if *every > 0 {
			return t.anchorEvery(ctx, id, *headsDir, *every)
		}
		_, err := t.anchor(ctx, id, *headsDir)
		return err
	default: // verify
		return t.verifyAgent(ctx, id, *headFile, *keysURL)
	}
}
