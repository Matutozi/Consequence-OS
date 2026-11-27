// Command shadow-score is an experiment: it decides each case in a policy
// test file twice, on the tools map's score as the gate does today and on
// a context score (the tools map's score times multipliers for how many
// records the call touches and whether data leaves the company), and
// prints both beside the decision the case says you'd want. Nothing it
// computes reaches the gate. See docs/shadow-score.md.
//
//	go run ./cmd/shadow-score -cases examples/shadow-score/cases.yaml -spec examples/shadow-score/spec.yaml
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/matutozi/consequence-os/internal/config"
	"github.com/matutozi/consequence-os/internal/policytest"
	"github.com/matutozi/consequence-os/internal/shadowscore"
)

func main() {
	if err := run(context.Background(), os.Stdout, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "shadow-score:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, out io.Writer, argv []string) error {
	fs := flag.NewFlagSet("shadow-score", flag.ContinueOnError)
	casesPath := fs.String("cases", "", "a policy test file (consequenced -test format); want: is the decision you'd want")
	specPath := fs.String("spec", "", "which arguments carry each tool's context, and the weights")
	configPath := fs.String("config", "", "the policy to decide with; default: the cases file's config:")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *casesPath == "" || *specPath == "" {
		return fmt.Errorf("-cases and -spec are both needed")
	}
	f, err := policytest.Read(*casesPath)
	if err != nil {
		return err
	}
	path := f.Config
	if *configPath != "" {
		path = *configPath
	}
	if path == "" {
		return fmt.Errorf("%s names no config:, so give -config", *casesPath)
	}
	cfg, err := config.LoadPolicy(path)
	if err != nil {
		return err
	}
	spec, err := readSpec(*specPath)
	if err != nil {
		return err
	}
	rows, err := shadowscore.Compare(ctx, cfg, f, spec)
	if err != nil {
		return fmt.Errorf("%s: %w", *casesPath, err)
	}
	fmt.Fprintf(out, "cases %s, policy %s, spec %s\n\n", *casesPath, path, *specPath)
	shadowscore.Print(out, rows)
	return nil
}

// readSpec reads the spec strictly, so a misspelt field isn't ignored.
func readSpec(path string) (shadowscore.Spec, error) {
	var s shadowscore.Spec
	data, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		return s, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}
