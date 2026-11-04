-- The audit log becomes a hash chain: each entry stores the previous
-- entry's hash and its own. Rows written before this migration keep empty
-- hashes; the chain starts at the first entry written after it.
ALTER TABLE audit_entries ADD COLUMN prev_hash text NOT NULL DEFAULT '';
ALTER TABLE audit_entries ADD COLUMN hash      text NOT NULL DEFAULT '';
