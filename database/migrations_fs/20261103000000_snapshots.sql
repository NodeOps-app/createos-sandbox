-- +goose Up
-- +goose StatementBegin
-- Reusable user snapshots are independent of the source sandbox's lifetime.
CREATE TABLE public.snapshots (
    id text NOT NULL,
    user_id text NOT NULL,
    -- Source sandbox for capture and recovery. No foreign key: a ready snapshot
    -- remains usable after the source sandbox is deleted.
    sandbox_id text NOT NULL,
    -- Display label only: names may repeat, including for the same user.
    name text,
    type text NOT NULL CHECK (type IN ('disk', 'full')),
    status text DEFAULT 'creating' NOT NULL
        CHECK (status IN ('creating', 'ready', 'failed', 'deleting')),
    -- Owning control region for lifecycle writes and recovery coordination;
    -- prevents both regions from driving the same operation. Not a restore
    -- placement restriction. Capture requests must reach the source sandbox's
    -- region before insertion; lifecycle queries enforce that ownership.
    region text NOT NULL,
    -- Host responsible for capture/upload; used to locate unfinished work
    -- during recovery. Does not pin restores to this host.
    host_id text,
    -- Captured defaults, independent of later changes to the shape catalog.
    shape text NOT NULL,
    vcpu integer NOT NULL CHECK (vcpu > 0),
    mem_mib integer NOT NULL CHECK (mem_mib > 0),
    -- Logical disk capacity; restore may grow this but must not shrink it.
    disk_mib bigint NOT NULL CHECK (disk_mib > 0),
    rootfs text NOT NULL,
    -- The manifest must retain the exact base-image identity and restore
    -- compatibility metadata as well as artifact sizes and checksums.
    snapshot_uri text,
    snapshot_manifest jsonb,
    size_bytes bigint DEFAULT 0 NOT NULL CHECK (size_bytes >= 0),
    error_code text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    ready_at timestamp with time zone,
    deleted_at timestamp with time zone
);

ALTER TABLE ONLY public.snapshots
    ADD CONSTRAINT snapshots_pkey PRIMARY KEY (id);

CREATE INDEX idx_snapshots_user_created
    ON public.snapshots (user_id, created_at DESC, id)
    WHERE deleted_at IS NULL;

CREATE INDEX idx_snapshots_sandbox
    ON public.snapshots (sandbox_id)
    WHERE deleted_at IS NULL;

-- Recovery work is scoped to the owning region and unfinished snapshots.
CREATE INDEX idx_snapshots_pending
    ON public.snapshots (region, status, created_at)
    WHERE deleted_at IS NULL AND status IN ('creating', 'deleting');
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS public.snapshots;
-- +goose StatementEnd
