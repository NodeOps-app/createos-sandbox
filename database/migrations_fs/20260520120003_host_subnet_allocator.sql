-- +goose Up
-- +goose StatementBegin
-- host_subnet_allocator
CREATE TABLE public.host_subnet_allocator (
    id integer DEFAULT 1 NOT NULL,
    next_index integer DEFAULT 0 NOT NULL,
    CONSTRAINT host_subnet_allocator_id_check CHECK ((id = 1))
);

ALTER TABLE ONLY public.host_subnet_allocator
    ADD CONSTRAINT host_subnet_allocator_pkey PRIMARY KEY (id);

-- Seed the singleton row so the first AssignHostSubnet allocation has
-- something to UPDATE. Without this, the first host's register returns
-- NULL subnet_cidr because the alloc CTE updates zero rows.
INSERT INTO public.host_subnet_allocator (id, next_index) VALUES (1, 0)
ON CONFLICT (id) DO NOTHING;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS public.host_subnet_allocator CASCADE;
-- +goose StatementEnd
