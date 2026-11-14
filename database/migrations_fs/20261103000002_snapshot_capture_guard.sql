-- +goose Up
-- Cleared from the active-capture set once an independent checkpoint exists
-- and the source VM is safe to use. Upload may still be in progress.
ALTER TABLE public.snapshots ADD COLUMN captured_at timestamptz;

CREATE UNIQUE INDEX idx_snapshots_active_capture
    ON public.snapshots (sandbox_id)
    WHERE status = 'creating' AND captured_at IS NULL AND deleted_at IS NULL;

-- +goose Down
DROP INDEX idx_snapshots_active_capture;
ALTER TABLE public.snapshots DROP COLUMN captured_at;
