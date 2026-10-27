-- +goose Up
-- +goose StatementBegin
ALTER TABLE public.api_keys DROP CONSTRAINT api_keys_pkey;
ALTER TABLE public.api_keys DROP COLUMN key;
ALTER TABLE public.api_keys
    ALTER COLUMN auth_type SET NOT NULL,
    ALTER COLUMN key_hash  SET NOT NULL;
DROP INDEX IF EXISTS idx_api_keys_key_hash;
ALTER TABLE public.api_keys
    ADD CONSTRAINT api_keys_pkey PRIMARY KEY (auth_type, key_hash);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE public.api_keys DROP CONSTRAINT api_keys_pkey;
ALTER TABLE public.api_keys ADD COLUMN key text;
CREATE INDEX idx_api_keys_key_hash ON public.api_keys (auth_type, key_hash);
ALTER TABLE public.api_keys
    ALTER COLUMN auth_type DROP NOT NULL,
    ALTER COLUMN key_hash  DROP NOT NULL;
-- +goose StatementEnd
