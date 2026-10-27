-- +goose Up
-- +goose StatementBegin

-- Per-host oversubscription factors for multi-dimensional admission
-- control. Stored as integer 10ths so cpu_overcommit_x10=20 means
-- "allow up to 2.0× physical_cores worth of vCPU commit". 0 means
-- "use the scheduler's default" (cpu=20, mem=10, disk=50).
--
-- These are operator-configurable knobs per host — different hardware
-- tiers (NVMe vs SATA, balanced vs big-mem) run with different ratios.
-- The scheduler's OvercommitFilter reads these on every schedule
-- decision; the host advertises them on register/heartbeat.
ALTER TABLE hosts
  ADD COLUMN cpu_overcommit_x10  integer NOT NULL DEFAULT 0,
  ADD COLUMN mem_overcommit_x10  integer NOT NULL DEFAULT 0,
  ADD COLUMN disk_overcommit_x10 integer NOT NULL DEFAULT 0;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE hosts
  DROP COLUMN IF EXISTS cpu_overcommit_x10,
  DROP COLUMN IF EXISTS mem_overcommit_x10,
  DROP COLUMN IF EXISTS disk_overcommit_x10;

-- +goose StatementEnd
