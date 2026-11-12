-- Pins of upstream tool definitions (internal/toolpin): the accepted
-- definition of each tool of each server, and a different one listed since,
-- waiting for a person to accept it. Definitions are kept as text, not
-- jsonb, so they come back byte for byte as hashed.
CREATE TABLE tool_pins (
    server          text        NOT NULL,
    tool            text        NOT NULL,
    hash            text        NOT NULL,
    definition      text        NOT NULL,
    pinned_at       timestamptz NOT NULL,
    accepted_by     text        NOT NULL DEFAULT '',
    seen            text        NOT NULL DEFAULT '',
    seen_definition text        NOT NULL DEFAULT '',
    seen_at         timestamptz,
    PRIMARY KEY (server, tool)
);
