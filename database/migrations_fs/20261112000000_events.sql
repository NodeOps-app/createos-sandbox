-- +goose Up
-- +goose StatementBegin
-- Operational history, independent of audit/webhook delivery. No foreign keys:
-- events must survive deletion of their resource. Each transition is a separate
-- row so repeated outages retain their own timelines. Owning regions write and
-- expire their own events; this table is not a source of lifecycle decisions.
CREATE TABLE public.events (
    id text PRIMARY KEY,
    region text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    severity text NOT NULL CHECK (severity IN ('normal', 'warning')),
    reason text NOT NULL,
    message text NOT NULL,
    component text NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_events_resource_time
    ON public.events (region, resource_type, resource_id, occurred_at DESC, id DESC);
CREATE INDEX idx_events_region_time ON public.events (region, occurred_at);
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS public.events;
