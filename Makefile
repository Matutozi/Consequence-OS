CONFIG ?= consequence.yaml
MOCK_ADDR ?= 127.0.0.1:9090

# Secrets from .env (created by `make env`) win over the dev defaults below.
# "-include" means: read it if it exists, carry on quietly if not.
-include .env

# Local development defaults only, used for anything .env doesn't set. Make
# real signing keys with `go run ./cmd/consequenced -genkeys` or `make env`.
# "export X ?= v" keeps a value .env already gave X, and exports it either way.
export CONSEQUENCE_KEY_SUPPORT_BOT ?= dev-support-bot-key
export CONSEQUENCE_KEY_RECEIVER_PAYMENTS ?= dev-payments-receiver-key
export CONSEQUENCE_ADMIN_TOKEN ?= dev-admin-token
export CONSEQUENCE_SIGNING_KEY_ED25519 ?= DtGH8ZUfSXLicN70bT3ZFCAY92rPDxyTXs4CTRnQkGA
export CONSEQUENCE_SIGNING_KEY_MLDSA87 ?= d981o8Ahw7SPWkniT-C-PSaH-CDeOSX9aZCCf4OfeYI

# Postgres for `make test-postgres`: any server where the tests may create
# and drop throwaway databases.
TEST_DATABASE_URL ?= postgres://postgres:test@127.0.0.1:55432/postgres

.PHONY: run check mock demo demo-approval demo-receipts test test-postgres bench lint env up down logs

run:
	go run ./cmd/consequenced -config $(CONFIG)

check:
	go run ./cmd/consequenced -config $(CONFIG) -check

# The mock refuses tool calls without a valid receipt, checking each one
# with the proxy's verify endpoint, the way a real receiver would.
mock:
	go run ./cmd/mockmcp -addr $(MOCK_ADDR) -require-receipts -verify-url http://127.0.0.1:8080

# Needs `make mock` and `make run` running in two other terminals.
demo:
	./scripts/demo.sh

# Same setup; you approve the held refund in the browser when asked.
demo-approval:
	./scripts/demo-approval.sh

demo-receipts:
	./scripts/demo-receipts.sh

test:
	go test ./...

test-postgres:
	CONSEQUENCE_TEST_DATABASE_URL=$(TEST_DATABASE_URL) go test ./internal/store/

# What the proxy adds to a call: compare AllowedCall with UpstreamDirect.
bench:
	go test -run '^$$' -bench . -benchmem ./internal/proxy/

lint:
	go vet ./...
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi

# --- docker compose ---

# Create .env with fresh random secrets (never overwrites an existing one).
env:
	./scripts/setup-env.sh

up: env
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f consequenced mockmcp
