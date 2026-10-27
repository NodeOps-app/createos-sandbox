-- +goose Up
-- +goose StatementBegin

-- mTLS dual-stack: track issued leaf certs so the CRL endpoint can
-- enumerate revoked serials. Host certs ride on the hosts row (one
-- live cert per host at a time). Non-host actors (control, ingress,
-- gateway, proxy, scheduler) get their own table keyed by role +
-- actor_id so a multi-replica role can hold N concurrent certs.
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

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_hosts_cert_revoked;
DROP INDEX IF EXISTS idx_actor_certs_revoked;
DROP TABLE IF EXISTS actor_certs;
ALTER TABLE hosts
  DROP COLUMN IF EXISTS cert_revoked_at,
  DROP COLUMN IF EXISTS cert_expires_at,
  DROP COLUMN IF EXISTS cert_serial;

-- +goose StatementEnd
