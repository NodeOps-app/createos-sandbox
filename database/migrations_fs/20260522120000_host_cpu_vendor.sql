-- +goose Up
-- Record the host's CPU vendor + family for cross-host snapshot
-- portability decisions. Populated by the host on register/heartbeat
-- from /proc/cpuinfo. No filtering on it yet — telemetry only. When
-- the cpu_compat scheduler plugin is wired into the pipeline these
-- columns become the source of truth.
ALTER TABLE hosts
    ADD COLUMN cpu_vendor TEXT,    -- e.g. "GenuineIntel", "AuthenticAMD"
    ADD COLUMN cpu_family TEXT;    -- e.g. "6:85:7" (family:model:stepping)

-- +goose Down
ALTER TABLE hosts
    DROP COLUMN cpu_vendor,
    DROP COLUMN cpu_family;
