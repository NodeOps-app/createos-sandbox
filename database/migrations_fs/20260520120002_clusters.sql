-- +goose Up
-- +goose StatementBegin
-- clusters
CREATE TABLE public.clusters (
    id text NOT NULL,
    name text NOT NULL,
    kubeconfig bytea NOT NULL,
    is_build_job_schedulable boolean DEFAULT true NOT NULL,
    region text,
    last_used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.clusters
    ADD CONSTRAINT clusters_pkey PRIMARY KEY (id);

CREATE INDEX idx_clusters_schedulable ON public.clusters USING btree (is_build_job_schedulable);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS public.clusters CASCADE;
-- +goose StatementEnd
