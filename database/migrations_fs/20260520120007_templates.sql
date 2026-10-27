-- +goose Up
-- +goose StatementBegin
-- templates
CREATE TABLE public.templates (
    id text NOT NULL,
    user_id text NOT NULL,
    name text NOT NULL,
    base text NOT NULL,
    status text NOT NULL,
    dockerfile text NOT NULL,
    size_bytes bigint DEFAULT 0 NOT NULL,
    ext4_size_bytes bigint DEFAULT 0 NOT NULL,
    sha256 text,
    built_in_cluster text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    built_at timestamp with time zone,
    deleted_at timestamp with time zone,
    attempts integer DEFAULT 0 NOT NULL
);

ALTER TABLE ONLY public.templates
    ADD CONSTRAINT templates_pkey PRIMARY KEY (id);

CREATE INDEX idx_templates_name_lookup ON public.templates USING btree (user_id, name, created_at DESC) WHERE ((status = 'ready'::text) AND (deleted_at IS NULL));

CREATE INDEX idx_templates_pending ON public.templates USING btree (created_at) WHERE (status = 'pending'::text);

CREATE INDEX idx_templates_user_status ON public.templates USING btree (user_id, status);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS public.templates CASCADE;
-- +goose StatementEnd
