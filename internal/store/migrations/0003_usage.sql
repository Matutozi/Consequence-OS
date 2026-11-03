-- Forwarded calls, for limit rules. One row per call (arg = ''), plus one
-- row per argument that a limit sums (arg = 'amount', value = 120). Only
-- those numbers are kept, never the rest of the arguments.
CREATE TABLE usage_records (
    seq      bigserial        PRIMARY KEY,
    agent_id text             NOT NULL,
    tool     text             NOT NULL,
    at       timestamptz      NOT NULL,
    arg      text             NOT NULL DEFAULT '',
    value    double precision NOT NULL DEFAULT 0
);
CREATE INDEX usage_records_lookup ON usage_records (agent_id, tool, arg, at);
CREATE INDEX usage_records_at ON usage_records (at);
