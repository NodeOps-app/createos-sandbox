-- +goose Up
-- +goose StatementBegin
-- Allow one user to mount the same disk at multiple paths in one sandbox.
-- The old PK (sandbox_id, disk_id) made that impossible. The new PK keys
-- by mount_path too, while idx_sandbox_disks_mount_path (added in the
-- previous migration) still enforces "no two disks at one path."
ALTER TABLE public.sandbox_disks
    DROP CONSTRAINT sandbox_disks_pkey;

ALTER TABLE public.sandbox_disks
    ADD CONSTRAINT sandbox_disks_pkey PRIMARY KEY (sandbox_id, disk_id, mount_path);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE public.sandbox_disks
    DROP CONSTRAINT sandbox_disks_pkey;

ALTER TABLE public.sandbox_disks
    ADD CONSTRAINT sandbox_disks_pkey PRIMARY KEY (sandbox_id, disk_id);
-- +goose StatementEnd
