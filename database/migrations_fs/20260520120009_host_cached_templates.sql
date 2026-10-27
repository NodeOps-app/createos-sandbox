-- +goose Up
-- +goose StatementBegin
-- host_cached_templates
CREATE TABLE public.host_cached_templates (
    host_id text NOT NULL,
    tpl_id text NOT NULL,
    fetched_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone DEFAULT now() NOT NULL,
    cached_until timestamp with time zone
);

ALTER TABLE ONLY public.host_cached_templates
    ADD CONSTRAINT host_cached_templates_pkey PRIMARY KEY (host_id, tpl_id);

CREATE INDEX idx_host_cached_templates_lru ON public.host_cached_templates USING btree (host_id, last_used_at);

CREATE INDEX idx_host_cached_templates_tpl ON public.host_cached_templates USING btree (tpl_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS public.host_cached_templates CASCADE;
-- +goose StatementEnd
