-- +goose Up
-- +goose StatementBegin
-- attempt: which build attempt produced this line. The same tpl_id
-- can be re-claimed by the janitor (see templates.attempts in
-- Postgres); without this column attempt-N lines would interleave
-- with attempt-1 lines indistinguishably. ClickHouse ORDER BY
-- columns are immutable post-creation so we keep (tpl_id, ts) as
-- the sort key; the reader filters via `WHERE attempt = ?`, which
-- is cheap because the table is always partitioned by day.
ALTER TABLE build_logs ADD COLUMN IF NOT EXISTS attempt UInt8 DEFAULT 1;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE build_logs DROP COLUMN IF EXISTS attempt;
-- +goose StatementEnd
