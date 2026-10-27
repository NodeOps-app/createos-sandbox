-- +goose Up
-- Partial index tuned to the pool-claim CTE. Without it, each claim
-- SELECT walks sandboxes_created_by_idx (all 'pool' rows) filtering by
-- region/shape/disk_mib/rootfs in memory, then sorts by created_at.
-- The partial index below matches the claim's WHERE + ORDER BY exactly
-- so PG picks the first satisfying row via an index scan (sub-ms even
-- at pool sizes in the thousands).
CREATE INDEX IF NOT EXISTS idx_sandboxes_pool_claim
  ON sandboxes (region, shape, disk_mib, created_at)
  WHERE created_by = 'pool' AND status = 'running';

-- +goose Down
DROP INDEX IF EXISTS idx_sandboxes_pool_claim;
