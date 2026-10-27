-- +goose Up
-- +goose StatementBegin
-- User-registered S3-compatible disks. credentials is an opaque AES-GCM
-- envelope written by control (internal/apiserver/diskcrypto); hosts never
-- read this column.
CREATE TABLE public.disks (
    id          text NOT NULL,
    user_id     text NOT NULL,
    name        text NOT NULL,
    kind        text NOT NULL,
    config      jsonb NOT NULL,
    credentials jsonb NOT NULL,
    created_at  timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at  timestamp with time zone
);

ALTER TABLE ONLY public.disks
    ADD CONSTRAINT disks_pkey PRIMARY KEY (id);

-- One name per user while the disk is live; same name reusable after soft-delete.
CREATE UNIQUE INDEX idx_disks_user_name
    ON public.disks (user_id, name) WHERE (deleted_at IS NULL);

CREATE INDEX idx_disks_user
    ON public.disks (user_id) WHERE (deleted_at IS NULL);

-- Per-sandbox attachments. mount_status surfaces guest-side mount result
-- back to the user. mount_error carries the agent's last failure string
-- (truncated to ~1 KiB by the reporter).
CREATE TABLE public.sandbox_disks (
    sandbox_id   text NOT NULL,
    disk_id      text NOT NULL,
    mount_path   text NOT NULL,
    mount_status text NOT NULL DEFAULT 'pending',
    mount_error  text,
    created_at   timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.sandbox_disks
    ADD CONSTRAINT sandbox_disks_pkey PRIMARY KEY (sandbox_id, disk_id);

ALTER TABLE ONLY public.sandbox_disks
    ADD CONSTRAINT sandbox_disks_sandbox_fk
    FOREIGN KEY (sandbox_id) REFERENCES public.sandboxes(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.sandbox_disks
    ADD CONSTRAINT sandbox_disks_disk_fk
    FOREIGN KEY (disk_id) REFERENCES public.disks(id);

CREATE INDEX idx_sandbox_disks_disk ON public.sandbox_disks (disk_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS public.sandbox_disks CASCADE;
DROP TABLE IF EXISTS public.disks CASCADE;
-- +goose StatementEnd
