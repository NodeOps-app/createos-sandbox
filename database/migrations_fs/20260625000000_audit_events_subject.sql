-- +goose Up
-- +goose StatementBegin
ALTER TABLE public.audit_events ADD COLUMN IF NOT EXISTS subject_type text;
ALTER TABLE public.audit_events ADD COLUMN IF NOT EXISTS subject_id text;
CREATE INDEX IF NOT EXISTS idx_audit_events_subject
    ON public.audit_events (subject_type, subject_id)
 WHERE subject_id IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_audit_events_subject;
ALTER TABLE public.audit_events DROP COLUMN IF EXISTS subject_id;
ALTER TABLE public.audit_events DROP COLUMN IF EXISTS subject_type;
-- +goose StatementEnd
