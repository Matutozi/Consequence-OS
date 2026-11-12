-- Archiving old audit entries (consequenced -archive-audit) deletes them
-- and leaves an anchor: the last archived entry's seq and hash, with the
-- signed head that vouches for them. The chain is checked from there.
-- One row at most: each archive replaces the anchor before it.
CREATE TABLE audit_anchor (
    only_row    boolean     PRIMARY KEY DEFAULT true CHECK (only_row),
    seq         bigint      NOT NULL,
    hash        text        NOT NULL,
    head        text        NOT NULL DEFAULT '',
    archived_at timestamptz NOT NULL
);
