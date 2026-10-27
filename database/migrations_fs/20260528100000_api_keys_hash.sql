-- +goose Up
-- +goose StatementBegin
-- API-key hashing — phase A.
--
-- Adds two columns:
--   auth_type  text   — which header the user sent (api_key, access_token, auth_token)
--   key_hash   bytea  — HMAC-SHA256(pepper, key) computed by control at write time
--
-- Backfill is NOT done here (no pgcrypto extension). Control's startup
-- has a one-shot pass that walks WHERE key_hash IS NULL, hashes the
-- plaintext key with the pepper, and UPDATEs in place. Idempotent.
--
-- The plaintext `key` column stays for backwards compatibility during
-- the soak window. Phase B will drop it + add UNIQUE (auth_type, key_hash).
ALTER TABLE public.api_keys
    ADD COLUMN auth_type text,
    ADD COLUMN key_hash  bytea;

-- Non-unique index now; phase B converts to UNIQUE once every row is
-- backfilled and old code is out of the picture.
CREATE INDEX idx_api_keys_key_hash ON public.api_keys (auth_type, key_hash);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_api_keys_key_hash;
ALTER TABLE public.api_keys
    DROP COLUMN IF EXISTS key_hash,
    DROP COLUMN IF EXISTS auth_type;
-- +goose StatementEnd
