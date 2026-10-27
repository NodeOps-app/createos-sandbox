-- +goose Up
-- +goose StatementBegin
-- networks
CREATE TABLE public.networks (
    id text NOT NULL,
    name text NOT NULL,
    owner text NOT NULL,
    vni integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

ALTER TABLE ONLY public.networks
    ADD CONSTRAINT networks_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.networks
    ADD CONSTRAINT networks_vni_key UNIQUE (vni);

CREATE UNIQUE INDEX idx_networks_owner_name ON public.networks USING btree (owner, name) WHERE (deleted_at IS NULL);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS public.networks CASCADE;
-- +goose StatementEnd
