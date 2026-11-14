package models

import (
	"context"
	"errors"
	"time"

	"github.com/NodeOps-app/createos-sandbox/database"

	"github.com/jackc/pgx/v5"
)

var (
	ErrSandboxAccessTokenExists   = errors.New("enabled sandbox access token already exists")
	ErrSandboxAccessTokenNotFound = errors.New("sandbox access token not found")
)

// SandboxAccessToken is the non-secret persisted metadata for one delegated
// sandbox credential. TokenHash is an HMAC digest, never plaintext.
type SandboxAccessToken struct {
	SandboxID string     `json:"sandbox_id"`
	TokenHash []byte     `json:"-"`
	TokenHint string     `json:"token_hint"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	RotatedAt *time.Time `json:"rotated_at,omitempty"`
}

func scanSandboxAccessToken(row pgx.Row) (*SandboxAccessToken, error) {
	var token SandboxAccessToken
	if err := row.Scan(
		&token.SandboxID,
		&token.TokenHash,
		&token.TokenHint,
		&token.CreatedBy,
		&token.CreatedAt,
		&token.RotatedAt,
	); err != nil {
		return nil, err
	}
	return &token, nil
}

func CreateSandboxAccessToken(ctx context.Context, d *database.Db, token SandboxAccessToken) error {
	q, err := query(d, "createSandboxAccessToken")
	if err != nil {
		return err
	}
	tag, err := d.Con.Exec(ctx, q,
		token.SandboxID, token.TokenHash, token.TokenHint,
		token.CreatedBy, token.CreatedAt,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrSandboxAccessTokenExists
	}
	return nil
}

func GetSandboxAccessToken(ctx context.Context, d *database.Db, sandboxID string) (*SandboxAccessToken, error) {
	q, err := query(d, "getSandboxAccessToken")
	if err != nil {
		return nil, err
	}
	token, err := scanSandboxAccessToken(d.Con.QueryRow(ctx, q, sandboxID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return token, err
}

func LookupSandboxAccessTokenByHash(ctx context.Context, d *database.Db, tokenHash []byte) (*SandboxAccessToken, error) {
	q, err := query(d, "lookupSandboxAccessTokenByHash")
	if err != nil {
		return nil, err
	}
	token, err := scanSandboxAccessToken(d.Con.QueryRow(ctx, q, tokenHash))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return token, err
}

func RotateSandboxAccessToken(ctx context.Context, d *database.Db, sandboxID string, tokenHash []byte, tokenHint string, rotatedAt time.Time) (*SandboxAccessToken, error) {
	q, err := query(d, "rotateSandboxAccessToken")
	if err != nil {
		return nil, err
	}
	token, err := scanSandboxAccessToken(d.Con.QueryRow(ctx, q, sandboxID, tokenHash, tokenHint, rotatedAt))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSandboxAccessTokenNotFound
	}
	return token, err
}

// DeleteSandboxAccessToken hard-deletes the credential. It is idempotent.
func DeleteSandboxAccessToken(ctx context.Context, d *database.Db, sandboxID string) (bool, error) {
	q, err := query(d, "deleteSandboxAccessToken")
	if err != nil {
		return false, err
	}
	tag, err := d.Con.Exec(ctx, q, sandboxID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}
