-- +goose Up
CREATE TABLE sandbox_access_tokens (
    sandbox_id text PRIMARY KEY
        REFERENCES sandboxes(id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,
    token_hint text NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL,
    rotated_at timestamptz
);

-- +goose Down
DROP TABLE IF EXISTS sandbox_access_tokens;
