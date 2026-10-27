-- +goose Up
-- +goose StatementBegin
-- sandbox_networks
CREATE TABLE public.sandbox_networks (
    sandbox_id text NOT NULL,
    network_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.sandbox_networks
    ADD CONSTRAINT sandbox_networks_pkey PRIMARY KEY (sandbox_id, network_id);

CREATE INDEX idx_sb_net_network ON public.sandbox_networks USING btree (network_id);

ALTER TABLE ONLY public.sandbox_networks
    ADD CONSTRAINT sandbox_networks_network_id_fkey FOREIGN KEY (network_id) REFERENCES public.networks(id);

ALTER TABLE ONLY public.sandbox_networks
    ADD CONSTRAINT sandbox_networks_sandbox_id_fkey FOREIGN KEY (sandbox_id) REFERENCES public.sandboxes(id) ON DELETE CASCADE;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS public.sandbox_networks CASCADE;
-- +goose StatementEnd
