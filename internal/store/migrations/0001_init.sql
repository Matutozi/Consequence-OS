-- Audit log: one row per decision. Never holds raw arguments.
CREATE TABLE audit_entries (
    seq         bigserial   PRIMARY KEY,           -- insertion order, breaks ties in time
    id          text        NOT NULL UNIQUE,
    time        timestamptz NOT NULL,
    agent_id    text        NOT NULL,
    owner_id    text        NOT NULL,
    tool        text        NOT NULL,
    params_hash text        NOT NULL DEFAULT '',
    summary     text        NOT NULL DEFAULT '',
    level       text        NOT NULL DEFAULT '',
    decision    text        NOT NULL DEFAULT '',
    rule        text        NOT NULL DEFAULT '',
    outcome     text        NOT NULL,
    approval_id text        NOT NULL DEFAULT '',
    receipt_id  text        NOT NULL DEFAULT '',
    detail      text        NOT NULL DEFAULT ''
);
CREATE INDEX audit_entries_time  ON audit_entries (time DESC, seq DESC);
CREATE INDEX audit_entries_agent ON audit_entries (agent_id, time DESC);
CREATE INDEX audit_entries_tool  ON audit_entries (tool, time DESC);

-- Held calls and their decisions.
CREATE TABLE approvals (
    seq         bigserial   PRIMARY KEY,
    id          text        NOT NULL UNIQUE,
    agent_id    text        NOT NULL,
    owner_id    text        NOT NULL,
    tool        text        NOT NULL,
    params_hash text        NOT NULL,
    summary     text        NOT NULL,
    arguments   text        NOT NULL,              -- canonical JSON; text, not jsonb, so the bytes stay exact
    level       text        NOT NULL,
    rule        text        NOT NULL,
    status      text        NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'used')),
    created_at  timestamptz NOT NULL,
    decided_at  timestamptz,
    decided_by  text        NOT NULL DEFAULT '',
    valid_until timestamptz,
    used_at     timestamptz
);
CREATE INDEX approvals_lookup ON approvals (agent_id, tool, params_hash, seq DESC);

-- One secret per approver per approval. Only hashes are stored.
CREATE TABLE approval_tokens (
    approval_id text  NOT NULL REFERENCES approvals (id) ON DELETE CASCADE,
    approver    text  NOT NULL,
    token_hash  bytea NOT NULL,
    PRIMARY KEY (approval_id, approver)
);

-- Receipts that have been used, for single use. Rows can be deleted once expired.
CREATE TABLE used_receipts (
    receipt_id text        PRIMARY KEY,
    used_at    timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX used_receipts_expiry ON used_receipts (expires_at);
