-- +goose Up
-- +goose StatementBegin

-- WireGuard host-mesh. Each host gets a Curve25519 keypair and a /32 from
-- 172.30.0.0/16. The mesh is global — every host peers with every other
-- host regardless of region — so WG IPs are partitioned per region within
-- the /16 (region slot N → 172.30.<N*64>.0/18, 16,384 hosts per region,
-- matching host_subnet_allocator's capacity). See assignHostWGIP query.

ALTER TABLE hosts
  ADD COLUMN wg_public_key bytea NOT NULL DEFAULT '\x'::bytea,
  ADD COLUMN wg_ip inet;

CREATE UNIQUE INDEX hosts_wg_ip_unique ON hosts (wg_ip) WHERE wg_ip IS NOT NULL;

CREATE TABLE host_wg_allocator (
  region     text PRIMARY KEY REFERENCES regions(name),
  next_index integer NOT NULL DEFAULT 1
);

INSERT INTO host_wg_allocator (region, next_index)
  SELECT name, 1 FROM regions
  ON CONFLICT (region) DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS host_wg_allocator;
DROP INDEX IF EXISTS hosts_wg_ip_unique;
ALTER TABLE hosts DROP COLUMN IF EXISTS wg_ip;
ALTER TABLE hosts DROP COLUMN IF EXISTS wg_public_key;

-- +goose StatementEnd
