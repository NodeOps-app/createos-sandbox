-- +goose Up
ALTER TABLE sandboxes
    ADD COLUMN labels jsonb NOT NULL DEFAULT '{}'::jsonb;

CREATE INDEX idx_sandboxes_labels_gin ON sandboxes USING gin (labels);

-- +goose Down
DROP INDEX IF EXISTS idx_sandboxes_labels_gin;
ALTER TABLE sandboxes DROP COLUMN IF EXISTS labels;
