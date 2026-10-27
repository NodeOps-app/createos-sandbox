-- +goose Up
-- +goose StatementBegin
-- Legacy duplicate of sandboxes.host_id. Now that every code path
-- writes both columns from a single value (and the host's reconcile-
-- tick has been migrated to query host_id), the legacy `host` column
-- can be retired. Backfill anything that drifted, then drop.
UPDATE sandboxes SET host_id = host WHERE host_id IS NULL OR host_id = '';
ALTER TABLE sandboxes DROP COLUMN host;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE sandboxes ADD COLUMN host text;
UPDATE sandboxes SET host = host_id;
-- +goose StatementEnd
