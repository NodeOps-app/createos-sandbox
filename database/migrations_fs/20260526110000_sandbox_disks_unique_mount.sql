-- +goose Up
-- +goose StatementBegin
-- One mount_path per sandbox: prevents two disks from trying to mount
-- at the same path inside the same VM, which would race or silently
-- shadow each other at the s3fs layer.
CREATE UNIQUE INDEX idx_sandbox_disks_mount_path
    ON public.sandbox_disks (sandbox_id, mount_path);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_sandbox_disks_mount_path;
-- +goose StatementEnd
