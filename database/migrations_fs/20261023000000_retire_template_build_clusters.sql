-- +goose Up
-- +goose StatementBegin
ALTER TABLE public.templates DROP COLUMN IF EXISTS built_in_cluster;
-- CASCADE removes Spock's replication-set membership, which is registered as
-- a dependency of the table. No application table depends on clusters.
DROP TABLE IF EXISTS public.clusters CASCADE;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE TABLE public.clusters (
    id text NOT NULL,
    name text NOT NULL,
    kubeconfig bytea NOT NULL,
    is_build_job_schedulable boolean DEFAULT true NOT NULL,
    region text,
    last_used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT clusters_pkey PRIMARY KEY (id)
);
CREATE INDEX idx_clusters_schedulable
    ON public.clusters USING btree (is_build_job_schedulable);
ALTER TABLE public.templates ADD COLUMN built_in_cluster text;
-- +goose StatementEnd
