-- +goose Up
-- +goose StatementBegin

-- billing_events is the outbox table for terminal sandbox lifecycle
-- events. Every billing-relevant status mutation in models/sandbox.go
-- writes a row here; a background worker in internal/billing/worker.go
-- drains rows whose status='pending' and POSTs them to the configured
-- billing webhook with HMAC-SHA256 signing.
--
-- sandbox_id is intentionally NOT a foreign key — events must survive
-- after the sandbox is destroyed (the destroyed event itself is the
-- last thing emitted for a sandbox).
CREATE TABLE public.billing_events (
    id              text PRIMARY KEY,
    sandbox_id      text NOT NULL,
    event_type      text NOT NULL,
    payload         jsonb NOT NULL,
    occurred_at     timestamp with time zone NOT NULL DEFAULT now(),

    -- Delivery state machine. Transitions:
    --   pending           → delivered          (worker got 2xx)
    --   pending           → superseded         (later event for same sandbox queued)
    --   pending           → internal_skip      (creator has is_internal=true)
    --   pending           → permanent_failure  (worker got 4xx ≠ 408/429)
    --   pending           → pending            (retryable error; bump attempts + next_attempt_at)
    -- Terminal states (everything except pending) never transition again.
    status          text NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'delivered', 'superseded',
                                       'internal_skip', 'permanent_failure')),
    delivered_at    timestamp with time zone,    -- stamped when status leaves 'pending'
    attempts        integer NOT NULL DEFAULT 0,
    last_error      text,                         -- raw error from the most recent delivery attempt
    next_attempt_at timestamp with time zone NOT NULL DEFAULT now()
);

-- Worker's hot query: pick up pending events whose backoff window has
-- elapsed. Partial index keeps the scan cheap regardless of how much
-- delivered history accumulates.
CREATE INDEX idx_billing_events_pending
    ON public.billing_events (next_attempt_at)
 WHERE status = 'pending';

-- Per-sandbox lookup for the supersession update inside
-- insertBillingEvent (collapse pending earlier events when a later
-- terminal event lands).
CREATE INDEX idx_billing_events_sandbox_pending
    ON public.billing_events (sandbox_id)
 WHERE status = 'pending';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS public.billing_events;
-- +goose StatementEnd
