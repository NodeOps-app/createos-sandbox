-- +goose Up
-- +goose StatementBegin
-- rootfs_catalog
CREATE TABLE public.rootfs_catalog (
    name text NOT NULL,
    description text,
    disabled boolean DEFAULT false NOT NULL,
    deprecated boolean DEFAULT false NOT NULL,
    successor text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.rootfs_catalog
    ADD CONSTRAINT rootfs_catalog_pkey PRIMARY KEY (name);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS public.rootfs_catalog CASCADE;
-- +goose StatementEnd
