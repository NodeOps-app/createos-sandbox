-- +goose Up
-- +goose StatementBegin

-- User-device WireGuard VPN. See docs/device-vpn.md.
--
-- Devices are the user-side counterpart to sandboxes: a registered
-- machine identified by its WG pubkey, holding a permanent IP from a
-- CGNAT pool. Devices attach to networks (N:M via device_networks),
-- inheriting reachability to VMs in those networks via the same
-- BPF VNI policy used for sandbox-to-sandbox traffic.
--
-- Relays are hosts with role='relay': they terminate user-side WG
-- on a separate wg-devices iface and forward into the existing
-- wg-hosts mesh. They reuse the host registration + CSR flow.

ALTER TABLE hosts
  ADD COLUMN role text NOT NULL DEFAULT 'compute';

-- For least-loaded relay picking.
CREATE INDEX hosts_role_status_idx ON hosts (role, status) WHERE role <> 'compute';

CREATE TABLE devices (
  id            text PRIMARY KEY,                   -- dev_<ulid>
  user_id       text NOT NULL,
  name          text NOT NULL,
  pubkey        bytea NOT NULL,
  client_ip     inet NOT NULL UNIQUE,
  hostname      text,                                -- captured at register
  os            text,
  created_at    timestamp with time zone DEFAULT now() NOT NULL,
  last_seen_at  timestamp with time zone,
  revoked_at    timestamp with time zone
);

CREATE INDEX devices_user_idx ON devices (user_id) WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX devices_user_name_idx ON devices (user_id, name) WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX devices_pubkey_idx ON devices (pubkey) WHERE revoked_at IS NULL;

CREATE TABLE device_networks (
  device_id     text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  network_id    text NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
  attached_at   timestamp with time zone DEFAULT now() NOT NULL,
  PRIMARY KEY (device_id, network_id)
);

CREATE INDEX device_networks_network_idx ON device_networks (network_id);

CREATE TABLE device_sessions (
  id              text PRIMARY KEY,                 -- wgs_<ulid>
  device_id       text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  relay_host_id   text NOT NULL REFERENCES hosts(id),
  endpoint_addr   text,                             -- client public ip:port, for clone-detect
  created_at      timestamp with time zone DEFAULT now() NOT NULL,
  expires_at      timestamp with time zone NOT NULL
);

CREATE INDEX device_sessions_device_idx ON device_sessions (device_id);
CREATE INDEX device_sessions_relay_active_idx ON device_sessions (relay_host_id, expires_at);
CREATE INDEX device_sessions_expires_idx ON device_sessions (expires_at);

-- CGNAT pool allocator for device client IPs. One row per region.
-- Region carries a /12 slice of 100.64.0.0/10 (CGNAT, RFC 6598) =
-- 1,048,576 devices per region, 4 regions = full /10.
CREATE TABLE device_ip_allocator (
  region     text PRIMARY KEY REFERENCES regions(name),
  next_index integer NOT NULL DEFAULT 1
);

INSERT INTO device_ip_allocator (region, next_index)
  SELECT name, 1 FROM regions
  ON CONFLICT (region) DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS device_sessions;
DROP TABLE IF EXISTS device_networks;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS device_ip_allocator;
DROP INDEX IF EXISTS hosts_role_status_idx;
ALTER TABLE hosts DROP COLUMN IF EXISTS role;

-- +goose StatementEnd
