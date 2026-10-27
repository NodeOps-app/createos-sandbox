-- +goose Up
-- +goose StatementBegin
-- One row per build log line. tpl_id+ts in the sort key makes the
-- "tail since ts" tail-poll (every 500ms from a follower) a single
-- granule scan. Partition by day so the TTL drops are O(1) part
-- removals; LowCardinality on tpl_id and level shrinks them to
-- dictionary-encoded byte columns since both have a small set of
-- distinct values across the whole table.
CREATE TABLE IF NOT EXISTS build_logs (
    tpl_id     LowCardinality(String),
    ts         DateTime64(6, 'UTC'),
    level      LowCardinality(String) DEFAULT 'info',
    line       String
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(ts)
ORDER BY (tpl_id, ts)
TTL toDateTime(ts) + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS build_logs;
-- +goose StatementEnd
