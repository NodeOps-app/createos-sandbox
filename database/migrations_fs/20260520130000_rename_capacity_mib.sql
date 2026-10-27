-- +goose Up
-- +goose StatementBegin
-- Rename hosts.capacity_mib → hosts.mem_capacity_mib for clarity (the
-- column is specifically the guest-RAM budget this host advertises, not
-- some other kind of capacity). Conditional: no-op on fresh installs
-- whose squashed 20260520120001_hosts migration already created the
-- column under the new name.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'hosts' AND column_name = 'capacity_mib'
    ) THEN
        ALTER TABLE public.hosts RENAME COLUMN capacity_mib TO mem_capacity_mib;
    END IF;
END$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'hosts' AND column_name = 'mem_capacity_mib'
    ) THEN
        ALTER TABLE public.hosts RENAME COLUMN mem_capacity_mib TO capacity_mib;
    END IF;
END$$;
-- +goose StatementEnd
