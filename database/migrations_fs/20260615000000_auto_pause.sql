-- +goose Up
ALTER TABLE sandboxes
    ADD COLUMN auto_pause_after_seconds int,
    ADD COLUMN last_activity_at         timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN last_metered_bytes       bigint      NOT NULL DEFAULT 0;

CREATE INDEX sandboxes_idle_sweep
    ON sandboxes (last_activity_at)
    WHERE status = 'running' AND auto_pause_after_seconds IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS sandboxes_idle_sweep;
ALTER TABLE sandboxes
    DROP COLUMN IF EXISTS auto_pause_after_seconds,
    DROP COLUMN IF EXISTS last_activity_at,
    DROP COLUMN IF EXISTS last_metered_bytes;
