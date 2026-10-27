-- +goose Up
-- +goose StatementBegin
-- Seed network_vni_allocator rows for the reserved region slots. The
-- 20260613000000_reserve_region_slots migration set up host_subnet_allocator
-- and host_wg_allocator pre-seeds for reserved-1/2/3, but missed the VNI
-- allocator — so activating a reserved region (rename to e.g. 'us') would
-- 500 on the first network create until an operator manually inserted a row.
--
-- VNI offset per region: divide the 24-bit VNI namespace (1..16777215)
-- into four ~4M slices keyed by regions.slot_index. The pair-allow-list
-- BPF model (option C, June 2026) made VNIs runtime-irrelevant — they
-- exist only as identifiers in Postgres — so per-slot offsets cost
-- nothing and buy globally-unique VNIs across regions for free.
-- Debugging "which region issued VNI 5_123_456?" becomes a divide-by-4M.
--
--   slot 0 (eu, existing)   → next_vni starts at 1            (already in flight)
--   slot 1 (reserved-1)     → next_vni starts at 4_194_304
--   slot 2 (reserved-2)     → next_vni starts at 8_388_608
--   slot 3 (reserved-3)     → next_vni starts at 12_582_912
--
-- 4_194_304 = 2^22. Powers-of-two boundaries keep the math obvious.
--
-- eu already has a row from the original schema (next_vni=1 at create
-- time, since incremented by real usage); we leave it alone. The other
-- three rows are NEW.

INSERT INTO network_vni_allocator (region, next_vni)
VALUES
  ('reserved-1', 4194304),
  ('reserved-2', 8388608),
  ('reserved-3', 12582912)
ON CONFLICT (region) DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM network_vni_allocator
 WHERE region IN ('reserved-1', 'reserved-2', 'reserved-3');
-- +goose StatementEnd
