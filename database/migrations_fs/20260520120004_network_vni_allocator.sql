-- +goose Up
-- +goose StatementBegin
-- network_vni_allocator
CREATE TABLE public.network_vni_allocator (
    id integer DEFAULT 1 NOT NULL,
    next_vni integer DEFAULT 1 NOT NULL,
    CONSTRAINT network_vni_allocator_id_check CHECK ((id = 1))
);

ALTER TABLE ONLY public.network_vni_allocator
    ADD CONSTRAINT network_vni_allocator_pkey PRIMARY KEY (id);

-- Seed the singleton row so the first network create's UPDATE has a
-- row to increment. Without this every CreateNetwork returns "no rows
-- in result set".
INSERT INTO public.network_vni_allocator (id, next_vni) VALUES (1, 1)
ON CONFLICT (id) DO NOTHING;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS public.network_vni_allocator CASCADE;
-- +goose StatementEnd
