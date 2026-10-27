-- +goose Up
-- +goose StatementBegin
-- regions catalog: operator-defined geographic placement zones. Hosts and
-- sandboxes reference a region by name; the scheduler rejects placements
-- whose region is missing or disabled.
CREATE TABLE public.regions (
    name text PRIMARY KEY,
    description text,
    country_code text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    disabled_at timestamp with time zone
);

CREATE INDEX idx_regions_active ON public.regions(name) WHERE disabled_at IS NULL;

INSERT INTO public.regions (name, description) VALUES ('eu', 'default region') ON CONFLICT DO NOTHING;

-- Each host is pinned to exactly one region. NOT NULL DEFAULT 'eu' so legacy
-- rows on an existing prod DB get a valid region automatically.
ALTER TABLE public.hosts ADD COLUMN region text NOT NULL DEFAULT 'eu';
CREATE INDEX idx_hosts_region ON public.hosts(region);

-- Tighten sandboxes.region (which was nullable in the squashed migration).
UPDATE public.sandboxes SET region = 'eu' WHERE region IS NULL;
ALTER TABLE public.sandboxes ALTER COLUMN region SET DEFAULT 'eu';
ALTER TABLE public.sandboxes ALTER COLUMN region SET NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE public.hosts DROP COLUMN IF EXISTS region;
DROP TABLE IF EXISTS public.regions CASCADE;
-- +goose StatementEnd
