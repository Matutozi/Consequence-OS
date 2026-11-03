-- Pending approvals now have a deadline for a decision, and a new status
-- for those that pass it. Older rows get no deadline (NULL).
ALTER TABLE approvals ADD COLUMN expires_at timestamptz;

ALTER TABLE approvals DROP CONSTRAINT approvals_status_check;
ALTER TABLE approvals ADD CONSTRAINT approvals_status_check
    CHECK (status IN ('pending', 'approved', 'rejected', 'used', 'expired'));

-- The sweep looks for pending approvals past their deadline.
CREATE INDEX approvals_pending_expiry ON approvals (expires_at) WHERE status = 'pending';
