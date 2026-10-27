-- +goose Up
-- +goose StatementBegin

-- audit_events: durable log of every audited action AND the outbox for
-- backend shipping. Modeled on billing_events — same status state
-- machine, same worker pattern (FOR UPDATE SKIP LOCKED + exponential
-- backoff). No separate queue table needed.
--
-- user_id intentionally NOT a foreign key — events must survive after
-- the user's api keys / account rows are deleted. Same reasoning as
-- billing_events.sandbox_id.
CREATE TABLE public.audit_events (
    id              text PRIMARY KEY,
    user_id         text NOT NULL,
    action          text NOT NULL,                       -- "<resource>.<verb>"
    operation_type  text NOT NULL
                    CHECK (operation_type IN ('create', 'modify', 'remove')),
    actor           text,                                 -- api_keys.name; nullable
    hashed_token    text,                                 -- sha256-hex of caller's plaintext token
    request_id      text,
    user_agent      text,
    ip_address      text,
    expires_at      timestamp with time zone,             -- server-set retention deadline
    metadata        jsonb NOT NULL,
    occurred_at     timestamp with time zone NOT NULL DEFAULT now(),
    is_internal     boolean NOT NULL DEFAULT false,

    -- Shipping state machine. Transitions:
    --   pending → shipped              (backend got 2xx)
    --   pending → permanent_failure    (backend got 4xx ≠ 408/429)
    --   pending → pending              (retryable; bump attempts + next)
    -- Terminal states never transition again.
    status              text NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'shipped', 'permanent_failure')),
    shipped_at          timestamp with time zone,
    attempts            integer NOT NULL DEFAULT 0,
    last_error          text,
    next_attempt_at     timestamp with time zone NOT NULL DEFAULT now()
);

-- User's view of their own audit trail, newest first.
CREATE INDEX idx_audit_events_user_time
    ON public.audit_events (user_id, occurred_at DESC);

-- Operator queries by action ("show me every disk.delete this week").
CREATE INDEX idx_audit_events_action_time
    ON public.audit_events (action, occurred_at DESC);

-- Retention sweeper hot path. Partial keeps the scan cheap when most
-- rows have no expiry set.
CREATE INDEX idx_audit_events_expiry
    ON public.audit_events (expires_at)
 WHERE expires_at IS NOT NULL;

-- Shipper hot path — mirrors idx_billing_events_pending. Scoped to
-- non-internal because is_internal=true rows are recorded but never
-- shipped (see claimPendingAuditEvents); without the scope the shipper
-- would scan every internal pending row forever.
CREATE INDEX idx_audit_events_pending
    ON public.audit_events (next_attempt_at)
 WHERE status = 'pending' AND is_internal = false;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS public.audit_events;
-- +goose StatementEnd
