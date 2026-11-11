-- Calls now carry a consequence score from 0 to 100. Audit entries keep
-- the score. Approvals keep the score and the reasons for it, to show the
-- approver. Audit entries don't keep the reasons: a consequence map may
-- derive them from the arguments, which the log never holds.
-- Rows from before this migration get score 0 and no reasons.
ALTER TABLE audit_entries ADD COLUMN score integer NOT NULL DEFAULT 0;
ALTER TABLE approvals ADD COLUMN score integer NOT NULL DEFAULT 0;
ALTER TABLE approvals ADD COLUMN reasons jsonb NOT NULL DEFAULT '[]';
