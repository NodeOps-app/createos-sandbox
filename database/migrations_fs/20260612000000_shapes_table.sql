-- +goose Up
-- +goose StatementBegin
CREATE TABLE shapes (
    id                text         PRIMARY KEY,
    vcpu              int          NOT NULL,
    mem_mib           int          NOT NULL,
    default_disk_mib  bigint       NOT NULL,
    cpu_quota_pct     int          NOT NULL DEFAULT 0,
    disabled          boolean      NOT NULL DEFAULT false,
    created_at        timestamptz  NOT NULL DEFAULT now(),
    updated_at        timestamptz  NOT NULL DEFAULT now()
);

-- Seed with the current static catalog. Source of truth before this
-- migration was internal/shapes/shapes.go's DefaultShapes slice. Keep
-- the seed in sync if DefaultShapes changes via code review.
INSERT INTO shapes (id, vcpu, mem_mib, default_disk_mib, cpu_quota_pct) VALUES
    ('s-1vcpu-256mb',    1, 256,  10240, 0),
    ('s-0.25vcpu-512mb', 1, 512,  10240, 25),
    ('s-0.5vcpu-1gb',    1, 1024, 10240, 50),
    ('s-1vcpu-1gb',      1, 1024, 10240, 0),
    ('s-1vcpu-2gb',      1, 2048, 10240, 0),
    ('s-2vcpu-2gb',      2, 2048, 10240, 0),
    ('s-2vcpu-4gb',      2, 4096, 10240, 0),
    ('s-4vcpu-4gb',      4, 4096, 10240, 0),
    ('s-4vcpu-8gb',      4, 8192, 10240, 0),
    ('s-8vcpu-8gb',      8, 8192, 10240, 0),
    ('s-8vcpu-16gb',     8, 16384, 10240, 0);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE shapes;
-- +goose StatementEnd
