-- +goose Up
-- +goose StatementBegin

-- Extend the existing regions table with slot_index. The slot determines
-- which VNI / subnet window the region owns; assigned at first registration
-- and never changes. Cap at 4 slots; raising the cap requires re-windowing.
ALTER TABLE regions ADD COLUMN IF NOT EXISTS slot_index integer;
-- Seed the existing single-region deployment as slot 0. Production today
-- is eu; the existing allocator rows belong to it.
UPDATE regions SET slot_index = 0 WHERE name = 'eu' AND slot_index IS NULL;
-- After backfill, enforce uniqueness + range. NULL slot_index remains
-- allowed for the brief window between INSERT and registerRegion claiming
-- a slot — the app-side bootstrap fills it before any allocator use.
CREATE UNIQUE INDEX IF NOT EXISTS regions_slot_index_unique ON regions (slot_index) WHERE slot_index IS NOT NULL;
ALTER TABLE regions ADD CONSTRAINT regions_slot_in_range CHECK (slot_index IS NULL OR (slot_index >= 0 AND slot_index < 4));

-- ── network_vni_allocator: drop singleton, key by region ───────────────
ALTER TABLE network_vni_allocator DROP CONSTRAINT IF EXISTS network_vni_allocator_id_check;
ALTER TABLE network_vni_allocator DROP CONSTRAINT IF EXISTS network_vni_allocator_pkey;
ALTER TABLE network_vni_allocator ADD COLUMN region text;
UPDATE network_vni_allocator SET region = 'eu' WHERE id = 1;
ALTER TABLE network_vni_allocator ALTER COLUMN region SET NOT NULL;
ALTER TABLE network_vni_allocator
  ADD CONSTRAINT network_vni_allocator_region_fk FOREIGN KEY (region) REFERENCES regions(name);
ALTER TABLE network_vni_allocator
  ADD CONSTRAINT network_vni_allocator_pkey PRIMARY KEY (region);
ALTER TABLE network_vni_allocator DROP COLUMN id;

-- ── host_subnet_allocator: drop singleton, key by region ───────────────
ALTER TABLE host_subnet_allocator DROP CONSTRAINT IF EXISTS host_subnet_allocator_id_check;
ALTER TABLE host_subnet_allocator DROP CONSTRAINT IF EXISTS host_subnet_allocator_pkey;
ALTER TABLE host_subnet_allocator ADD COLUMN region text;
UPDATE host_subnet_allocator SET region = 'eu' WHERE id = 1;
ALTER TABLE host_subnet_allocator ALTER COLUMN region SET NOT NULL;
ALTER TABLE host_subnet_allocator
  ADD CONSTRAINT host_subnet_allocator_region_fk FOREIGN KEY (region) REFERENCES regions(name);
ALTER TABLE host_subnet_allocator
  ADD CONSTRAINT host_subnet_allocator_pkey PRIMARY KEY (region);
ALTER TABLE host_subnet_allocator DROP COLUMN id;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- One-way migration. Restoring the singleton shape from per-region rows
-- requires picking which region's counter to keep — operator decision,
-- not automatic.
SELECT 1;
-- +goose StatementEnd
