-- +goose Up
-- +goose StatementBegin

-- Tighten idx_audit_events_pending to exclude is_internal=true rows.
-- The shipper's claimPendingAuditEvents was updated to filter
-- is_internal=false; without re-scoping the partial index the planner
-- still scans internal pending rows it will never deliver.
DROP INDEX IF EXISTS idx_audit_events_pending;
CREATE INDEX idx_audit_events_pending
    ON public.audit_events (next_attempt_at)
 WHERE status = 'pending' AND is_internal = false;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_audit_events_pending;
CREATE INDEX idx_audit_events_pending
    ON public.audit_events (next_attempt_at)
 WHERE status = 'pending';
-- +goose StatementEnd
