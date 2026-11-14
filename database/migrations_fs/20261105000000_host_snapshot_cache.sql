-- +goose Up
-- Advisory cache inventory, replaced by each authenticated host heartbeat.
-- No foreign keys: eviction and snapshot soft deletion need no coordination.
ALTER TABLE public.hosts ADD COLUMN cached_snapshots jsonb NOT NULL DEFAULT '[]'::jsonb;

-- +goose Down
ALTER TABLE public.hosts DROP COLUMN cached_snapshots;
