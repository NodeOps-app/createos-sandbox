// Package audit emits typed lifecycle events to the backend audit log.
// Internal callers (api_keys.is_internal=true) are persisted to
// audit_events with is_internal=true so the backend can filter them.
//
// # Sensitive-data policy
//
// NEVER include: api keys, mTLS private keys, disk credentials,
// bootstrap tokens, webhook secrets, HMAC pepper, exec args, raw
// Dockerfiles, env-var values, file bodies.
//
// HASH or fingerprint when identity matters: tokens via HashToken,
// ssh pubkeys via FingerprintSSH.
//
// CI grep to catch regressions:
//
//	grep -rE 'audit\..*Emit|audit\.Metadata' internal/ \
//	  | grep -iE 'secret|token|password|credential|private_key|pubkey_raw'
package audit

import (
	"context"

	"encoding/json"
	"github.com/jackc/pgx/v5"
	"time"
)

type OperationType string

const (
	OperationCreate OperationType = "create"
	OperationModify OperationType = "modify"
	OperationRemove OperationType = "remove"
)

type Action string

type Event struct {
	ID            string          `json:"id"`
	UserID        string          `json:"user_id"`
	Action        Action          `json:"action"`
	OperationType OperationType   `json:"operation_type"`
	Actor         *string         `json:"actor,omitempty"`
	HashedToken   *string         `json:"hashed_token,omitempty"`
	RequestID     *string         `json:"request_id,omitempty"`
	UserAgent     *string         `json:"user_agent,omitempty"`
	IPAddress     *string         `json:"ip_address,omitempty"`
	ExpiresAt     *time.Time      `json:"expires_at,omitempty"`
	Metadata      json.RawMessage `json:"metadata"`
	OccurredAt    time.Time       `json:"occurred_at"`
	IsInternal    bool            `json:"is_internal"`
}

// Metadata is a marker so Build* helpers return a typed value the
// caller can't confuse with an arbitrary map.
type Metadata interface{ isAuditMetadata() }

type Context struct {
	UserID      string
	IsInternal  bool
	Actor       string
	HashedToken string
	RequestID   string
	UserAgent   string
	IPAddress   string
	SubjectType string
	SubjectID   string
}

// Emit is fire-and-forget: returns without blocking on outbound
// delivery. Errors are logged, never propagated — audit must not break
// the happy path of the operation it's recording.
//
// EmitInTx writes the audit row inside the caller's pgx transaction so
// business mutation + audit either both commit or both roll back. Used
// for the pool-claim flow where owner change and audit must be atomic.
type Emitter interface {
	Emit(ctx context.Context, ac Context, action Action, op OperationType, md Metadata)
	EmitInTx(ctx context.Context, tx pgx.Tx, ac Context, action Action, op OperationType, md Metadata) error
}

type Noop struct{}

func (Noop) Emit(context.Context, Context, Action, OperationType, Metadata) {}

func (Noop) EmitInTx(context.Context, pgx.Tx, Context, Action, OperationType, Metadata) error {
	return nil
}
