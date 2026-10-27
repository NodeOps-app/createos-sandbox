-- +goose Up
-- +goose StatementBegin
-- hosts
CREATE TABLE public.hosts (
    id text NOT NULL,
    addr text,
    status text,
    mem_capacity_mib integer,
    in_use_mib integer,
    vm_count integer,
    cpu_count integer,
    disk_total_mib bigint,
    disk_used_mib bigint,
    max_vms integer,
    rootfses text[],
    registered_at timestamp with time zone,
    last_seen timestamp with time zone,
    labels jsonb DEFAULT '{}'::jsonb NOT NULL,
    scheduling_disabled boolean DEFAULT false NOT NULL,
    public_key bytea,
    subnet_cidr text,
    underlay_ip text
);

ALTER TABLE ONLY public.hosts
    ADD CONSTRAINT hosts_pkey PRIMARY KEY (id);

CREATE INDEX hosts_status_idx ON public.hosts USING btree (status);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS public.hosts CASCADE;
-- +goose StatementEnd
