-- +goose Up
-- Stamp the CPU vendor + family the sandbox was first booted under.
-- Once a snapshot exists, this is the only vendor it can ever be
-- restored on (firecracker bakes source CPUID into vmstate). Persisting
-- it per-row lets the scheduler's cpu_compat filter pin resumes to a
-- matching host without joining `hosts` via `cached_host_id` (which can
-- dangle when the original host is decommissioned).
--
-- Telemetry / future-use only today: cpu_compat is registered but not
-- in DefaultPipelineSpec. Operators flip it on after every active row
-- has been backfilled.
ALTER TABLE sandboxes
    ADD COLUMN cpu_vendor TEXT,    -- e.g. "GenuineIntel", "AuthenticAMD"
    ADD COLUMN cpu_family TEXT;    -- family:model:stepping

-- +goose Down
ALTER TABLE sandboxes
    DROP COLUMN cpu_vendor,
    DROP COLUMN cpu_family;
