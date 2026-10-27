-- +goose Up
-- +goose StatementBegin

-- wg-devices public key for hosts with role='relay'. Distinct from
-- wg_public_key (which is the wg-hosts mesh pubkey). Used by the
-- session-create handler to fill the client wg-quick config — without
-- this column the handler conflates the two keys and hands clients
-- the wrong pubkey, so handshake never completes.
ALTER TABLE hosts ADD COLUMN relay_devices_pubkey bytea;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE hosts DROP COLUMN IF EXISTS relay_devices_pubkey;
-- +goose StatementEnd
