-- +goose Up
-- +goose StatementBegin
-- Make the disks (user_id, name) uniqueness partial so soft-deleted rows
-- (deleted_at IS NOT NULL) don't block a user from reclaiming the same
-- name on a fresh `POST /v1/disks`. Same pattern as idx_networks_owner_name
-- in 20260520120100_networks.sql / 20260520120008_networks.sql.
--
-- Defensive: drops the existing index whether it was full or already
-- partial, then recreates as partial. A unique constraint with the same
-- name (in case an older deployment used ALTER TABLE ... ADD CONSTRAINT
-- instead of CREATE UNIQUE INDEX) is dropped first.
ALTER TABLE public.disks DROP CONSTRAINT IF EXISTS idx_disks_user_name;
DROP INDEX IF EXISTS public.idx_disks_user_name;

CREATE UNIQUE INDEX idx_disks_user_name
    ON public.disks (user_id, name) WHERE (deleted_at IS NULL);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS public.idx_disks_user_name;

CREATE UNIQUE INDEX idx_disks_user_name
    ON public.disks (user_id, name);
-- +goose StatementEnd
