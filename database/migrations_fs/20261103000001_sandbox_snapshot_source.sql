-- +goose Up
-- Creation provenance only. Taking a snapshot of this sandbox does not change
-- this field. NULL means the sandbox was not created from a reusable snapshot.
-- No foreign key: provenance can outlive the source snapshot record.
ALTER TABLE public.sandboxes ADD COLUMN snapshot_id text;

-- +goose Down
ALTER TABLE public.sandboxes DROP COLUMN snapshot_id;
