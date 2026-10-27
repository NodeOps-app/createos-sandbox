-- +goose Up
-- drain_pause_attempts tracks how many times the sweep CronJob has
-- tried to pause this sandbox during host drain and the HTTP call to
-- the owning host failed. Counter increments only when pause fails to
-- *start* (status stays 'running'); a successful pause-trigger that
-- later hangs is caught by the separate stuck-pausing watchdog. At
-- attempts>=5 sweep falls back to destroy so a misbehaving host can't
-- permanently block drain completion.
--
-- Lives in Postgres because sweep is a one-shot CronJob — there's no
-- in-process memory between runs. Replaces the in-memory map control
-- carried in its long-running drain ticker.
ALTER TABLE sandboxes
  ADD COLUMN drain_pause_attempts integer NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE sandboxes DROP COLUMN drain_pause_attempts;
