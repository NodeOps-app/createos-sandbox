-- +goose Up
-- +goose StatementBegin
-- api_keys
CREATE TABLE public.api_keys (
    key text NOT NULL,
    user_id text,
    name text,
    created_at timestamp with time zone,
    revoked boolean,
    is_internal boolean DEFAULT false NOT NULL,
    expires_at timestamp with time zone
);

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_pkey PRIMARY KEY (key);

CREATE INDEX api_keys_user_idx ON public.api_keys USING btree (user_id);

CREATE INDEX idx_api_keys_external_expiry ON public.api_keys USING btree (expires_at) WHERE ((is_internal = false) AND (expires_at IS NOT NULL));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS public.api_keys CASCADE;
-- +goose StatementEnd
