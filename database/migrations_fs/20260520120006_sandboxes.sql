-- +goose Up
-- +goose StatementBegin
-- sandboxes
CREATE TABLE public.sandboxes (
    id text NOT NULL,
    host text,
    host_id text,
    status text,
    mode text,
    ip text,
    mac text,
    vcpu integer,
    mem_mib integer,
    disk_mib bigint,
    shape text,
    rootfs text,
    created_by text,
    created_at timestamp with time zone,
    running_at timestamp with time zone,
    destroyed_at timestamp with time zone,
    spawn_ms double precision,
    error_text text,
    note text,
    egress text[],
    ssh_pubkeys text[],
    bandwidth_quota_bytes bigint,
    bandwidth_used_bytes bigint,
    bandwidth_capped boolean,
    api_sock text,
    container_id text,
    fc_pid integer,
    overlay_path text,
    ingress_enabled boolean DEFAULT false NOT NULL,
    bandwidth_ingress_bytes bigint DEFAULT 0 NOT NULL,
    region text DEFAULT 'eu' NOT NULL,
    secret_token text,
    envs jsonb DEFAULT '{}'::jsonb NOT NULL,
    paused_at timestamp with time zone,
    snapshot_uri text,
    snapshot_manifest jsonb,
    cached_host_id text,
    cached_until timestamp with time zone,
    last_resumed_at timestamp with time zone,
    resume_failed_hosts text[],
    last_resume_error text,
    last_resume_attempt_at timestamp with time zone,
    last_pause_error text,
    last_pause_attempt_at timestamp with time zone,
    forked_from text,
    bundle_uploaded_at timestamp with time zone,
    name text
);

ALTER TABLE ONLY public.sandboxes
    ADD CONSTRAINT sandboxes_pkey PRIMARY KEY (id);

CREATE INDEX idx_sandboxes_cached_host_id ON public.sandboxes USING btree (cached_host_id) WHERE (cached_host_id IS NOT NULL);

CREATE INDEX idx_sandboxes_forked_from ON public.sandboxes USING btree (forked_from) WHERE (forked_from IS NOT NULL);

CREATE INDEX idx_sandboxes_pending_upload ON public.sandboxes USING btree (cached_host_id) WHERE ((status = 'paused'::text) AND (bundle_uploaded_at IS NULL));

CREATE INDEX idx_sandboxes_status_host_id ON public.sandboxes USING btree (status, host_id) WHERE (status = ANY (ARRAY['creating'::text, 'running'::text]));

CREATE INDEX idx_sandboxes_status_transient ON public.sandboxes USING btree (status) WHERE (status = ANY (ARRAY['pausing'::text, 'paused'::text, 'resuming'::text, 'forking'::text, 'error'::text, 'destroying'::text]));

CREATE UNIQUE INDEX idx_sandboxes_user_name ON public.sandboxes USING btree (created_by, name) WHERE (status <> ALL (ARRAY['destroyed'::text, 'failed'::text]));

CREATE INDEX sandboxes_created_by_idx ON public.sandboxes USING btree (created_by);

CREATE INDEX sandboxes_host_idx ON public.sandboxes USING btree (host);

CREATE INDEX sandboxes_ip_idx ON public.sandboxes USING btree (ip);

CREATE INDEX sandboxes_status_idx ON public.sandboxes USING btree (status);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS public.sandboxes CASCADE;
-- +goose StatementEnd
