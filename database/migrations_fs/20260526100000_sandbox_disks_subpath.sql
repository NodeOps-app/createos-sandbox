-- +goose Up
-- +goose StatementBegin
-- Per-attachment sub-folder inside the bucket. Empty string = mount
-- the bucket root (existing behavior); non-empty = pass `bucket:/sub_path`
-- to s3fs so the user sees only that prefix as the mount.
ALTER TABLE public.sandbox_disks
    ADD COLUMN sub_path text NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE public.sandbox_disks DROP COLUMN sub_path;
-- +goose StatementEnd
