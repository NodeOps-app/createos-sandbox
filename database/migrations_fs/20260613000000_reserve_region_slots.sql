-- +goose Up
-- +goose StatementBegin
-- Pre-seed the remaining region slots (1, 2, 3) with `reserved-N`
-- placeholders so the per-region CIDR offset is locked in NOW and adding
-- a real region later is a one-line UPDATE instead of a coordinated
-- multi-table change. Address-space layout:
--
--   slot 0 → 10.0.0.0/10   (VM)  + 172.30.0.0/18    (WG)   ← eu (existing)
--   slot 1 → 10.64.0.0/10  (VM)  + 172.30.64.0/18   (WG)   ← reserved-1
--   slot 2 → 10.128.0.0/10 (VM)  + 172.30.128.0/18  (WG)   ← reserved-2
--   slot 3 → 10.192.0.0/10 (VM)  + 172.30.192.0/18  (WG)   ← reserved-3
--
-- The reserved rows have disabled_at = now() so the scheduler/ingress
-- treat them as inactive (no placements). To activate a region:
--   UPDATE regions SET name='us', disabled_at=NULL WHERE name='reserved-1';
-- The ON UPDATE CASCADE on the FKs below propagates the rename through
-- host_subnet_allocator, host_wg_allocator, and network_vni_allocator
-- atomically — one statement activates the region.

-- ON UPDATE CASCADE the three region FKs so the rename-to-activate
-- workflow cascades to the allocator rows. The default NO ACTION would
-- block the rename while child rows reference the old name.
ALTER TABLE host_subnet_allocator
  DROP CONSTRAINT host_subnet_allocator_region_fk;
ALTER TABLE host_subnet_allocator
  ADD CONSTRAINT host_subnet_allocator_region_fk
  FOREIGN KEY (region) REFERENCES regions(name) ON UPDATE CASCADE;

ALTER TABLE host_wg_allocator
  DROP CONSTRAINT host_wg_allocator_region_fkey;
ALTER TABLE host_wg_allocator
  ADD CONSTRAINT host_wg_allocator_region_fkey
  FOREIGN KEY (region) REFERENCES regions(name) ON UPDATE CASCADE;

ALTER TABLE network_vni_allocator
  DROP CONSTRAINT network_vni_allocator_region_fk;
ALTER TABLE network_vni_allocator
  ADD CONSTRAINT network_vni_allocator_region_fk
  FOREIGN KEY (region) REFERENCES regions(name) ON UPDATE CASCADE;

INSERT INTO regions (name, slot_index, disabled_at, description, country_code)
VALUES
  ('reserved-1', 1, NOW(), 'Reserved slot 1 — rename to activate', NULL),
  ('reserved-2', 2, NOW(), 'Reserved slot 2 — rename to activate', NULL),
  ('reserved-3', 3, NOW(), 'Reserved slot 3 — rename to activate', NULL)
ON CONFLICT (name) DO NOTHING;

-- Seed matching allocator rows so the first host in a new region just
-- works after the regions.name UPDATE — no allocator INSERT needed.
INSERT INTO host_subnet_allocator (region, next_index)
VALUES ('reserved-1', 0), ('reserved-2', 0), ('reserved-3', 0)
ON CONFLICT (region) DO NOTHING;

INSERT INTO host_wg_allocator (region, next_index)
VALUES ('reserved-1', 0), ('reserved-2', 0), ('reserved-3', 0)
ON CONFLICT (region) DO NOTHING;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM host_wg_allocator WHERE region IN ('reserved-1','reserved-2','reserved-3');
DELETE FROM host_subnet_allocator WHERE region IN ('reserved-1','reserved-2','reserved-3');
DELETE FROM regions WHERE name IN ('reserved-1','reserved-2','reserved-3');

ALTER TABLE host_subnet_allocator
  DROP CONSTRAINT host_subnet_allocator_region_fk;
ALTER TABLE host_subnet_allocator
  ADD CONSTRAINT host_subnet_allocator_region_fk
  FOREIGN KEY (region) REFERENCES regions(name);

ALTER TABLE host_wg_allocator
  DROP CONSTRAINT host_wg_allocator_region_fkey;
ALTER TABLE host_wg_allocator
  ADD CONSTRAINT host_wg_allocator_region_fkey
  FOREIGN KEY (region) REFERENCES regions(name);

ALTER TABLE network_vni_allocator
  DROP CONSTRAINT network_vni_allocator_region_fk;
ALTER TABLE network_vni_allocator
  ADD CONSTRAINT network_vni_allocator_region_fk
  FOREIGN KEY (region) REFERENCES regions(name);
-- +goose StatementEnd
