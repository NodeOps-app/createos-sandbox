-- +goose Up
-- +goose StatementBegin

-- Single-table cert ledger. Append-only: every leaf the in-process CA
-- mints lives here as one row. Rotation inserts a new row + tombstones
-- the predecessor (immediate for non-hosts, scheduled-grace for hosts).
-- pgEdge / Spock multi-master compatible — PK is a 128-bit random hex
-- serial (no SERIAL, no SEQUENCE), `replaced_by` is plain text (no
-- self-FK because Spock can't cleanly resolve cross-row constraints
-- during replay).
CREATE TABLE issued_certs (
    cert_serial         text        PRIMARY KEY,
    subject_kind        text        NOT NULL,
    subject_id          text        NOT NULL,
    issued_at           timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz NOT NULL,
    revoked_at          timestamptz,
    revoked_by          text,
    replaced_by         text,
    scheduled_revoke_at timestamptz
);

CREATE INDEX idx_issued_certs_subject ON issued_certs (subject_kind, subject_id);
CREATE INDEX idx_issued_certs_revoked ON issued_certs (revoked_at) WHERE revoked_at IS NOT NULL;
CREATE INDEX idx_issued_certs_expires ON issued_certs (expires_at);
CREATE INDEX idx_issued_certs_scheduled
    ON issued_certs (scheduled_revoke_at)
 WHERE scheduled_revoke_at IS NOT NULL AND revoked_at IS NULL;

CREATE VIEW cert_status AS
SELECT
    cert_serial, subject_kind, subject_id,
    issued_at, expires_at, revoked_at, revoked_by, replaced_by, scheduled_revoke_at,
    CASE
        WHEN revoked_at IS NOT NULL  THEN 'revoked'
        WHEN expires_at <= now()     THEN 'expired'
        ELSE                              'active'
    END AS status
FROM issued_certs;

-- Replace the legacy split design wholesale.
DROP TABLE IF EXISTS actor_certs;
ALTER TABLE hosts
  DROP COLUMN IF EXISTS cert_serial,
  DROP COLUMN IF EXISTS cert_expires_at,
  DROP COLUMN IF EXISTS cert_revoked_at;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE hosts
  ADD COLUMN IF NOT EXISTS cert_serial      text,
  ADD COLUMN IF NOT EXISTS cert_expires_at  timestamptz,
  ADD COLUMN IF NOT EXISTS cert_revoked_at  timestamptz;

CREATE TABLE IF NOT EXISTS actor_certs (
  role         text NOT NULL,
  actor_id     text NOT NULL,
  cert_serial  text NOT NULL UNIQUE,
  expires_at   timestamptz NOT NULL,
  issued_at    timestamptz NOT NULL DEFAULT now(),
  revoked_at   timestamptz,
  PRIMARY KEY (role, actor_id)
);

CREATE INDEX IF NOT EXISTS idx_actor_certs_revoked ON actor_certs(revoked_at) WHERE revoked_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_hosts_cert_revoked  ON hosts(cert_revoked_at)  WHERE cert_revoked_at IS NOT NULL;

DROP VIEW IF EXISTS cert_status;
DROP INDEX IF EXISTS idx_issued_certs_scheduled;
DROP INDEX IF EXISTS idx_issued_certs_expires;
DROP INDEX IF EXISTS idx_issued_certs_revoked;
DROP INDEX IF EXISTS idx_issued_certs_subject;
DROP TABLE IF EXISTS issued_certs;

-- +goose StatementEnd
