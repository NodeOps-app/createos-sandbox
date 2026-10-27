package models

import (
	"context"
	"errors"
	"time"

	"github.com/NodeOps-app/sandbox/database"

	"github.com/jackc/pgx/v5"
)

// APIKey is one row of the api_keys table.
//
// Lookups are by (AuthType, KeyHash) — the PK. KeyHash is the
// HMAC-SHA256(pepper, plaintext) digest control writes at upsert time.
// The plaintext token never lands on disk.
type APIKey struct {
	UserID     string     `json:"user_id" sql:"user_id"`
	Name       *string    `json:"name,omitempty" sql:"name"`
	CreatedAt  time.Time  `json:"created_at" sql:"created_at"`
	Revoked    bool       `json:"revoked" sql:"revoked"`
	IsInternal bool       `json:"is_internal" sql:"is_internal"` // operator-issued; never expires, never re-validated externally
	ExpiresAt  *time.Time `json:"expires_at" sql:"expires_at"`   // external-cache TTL; nil for internal rows
	AuthType   string     `json:"auth_type" sql:"auth_type"`
	KeyHash    []byte     `json:"-" sql:"key_hash"`
}

func UpsertAPIKey(ctx context.Context, d *database.Db, k APIKey) error {
	q, err := query(d, "upsertApiKey")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q,
		k.UserID, k.Name, k.CreatedAt, k.Revoked, k.IsInternal, k.ExpiresAt,
		k.AuthType, k.KeyHash,
	)
	return err
}

func RevokeAPIKeyByHash(ctx context.Context, d *database.Db, authType string, keyHash []byte) error {
	q, err := query(d, "revokeApiKey")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, authType, keyHash)
	return err
}

// LookupAPIKeyByHash returns the row for (authType, keyHash) or nil
// with no error if the row is absent — caller falls through to
// upstream validation.
func LookupAPIKeyByHash(ctx context.Context, d *database.Db, authType string, keyHash []byte) (*APIKey, error) {
	q, err := query(d, "lookupApiKeyByHash")
	if err != nil {
		return nil, err
	}
	row := d.Con.QueryRow(ctx, q, authType, keyHash)
	var k APIKey
	err = row.Scan(&k.UserID, &k.Name, &k.CreatedAt, &k.Revoked, &k.IsInternal, &k.ExpiresAt, &k.AuthType, &k.KeyHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// DeleteAPIKeyByHash inline-drops one row when upstream /v1/users/me
// returns 401/403/404. Idempotent.
func DeleteAPIKeyByHash(ctx context.Context, d *database.Db, authType string, keyHash []byte) error {
	q, err := query(d, "deleteApiKeyByHash")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, authType, keyHash)
	return err
}

func ListAPIKeys(ctx context.Context, d *database.Db) ([]APIKey, error) {
	q, err := query(d, "listApiKeys")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIKey
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(&k.UserID, &k.Name, &k.CreatedAt, &k.Revoked, &k.IsInternal, &k.ExpiresAt, &k.AuthType, &k.KeyHash); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// ExpiredAPIKey identifies a row that was just GC'd by
// DeleteExpiredExternalAPIKeys. Callers use it to invalidate any
// in-process cache keyed on (auth_type, key_hash).
type ExpiredAPIKey struct {
	AuthType string
	KeyHash  []byte
}

// DeleteExpiredExternalAPIKeys drops external-cache rows whose
// expires_at is before `before`. Internal rows are skipped. Returns
// the (auth_type, key_hash) pairs deleted so callers can invalidate
// any in-process cache.
func DeleteExpiredExternalAPIKeys(ctx context.Context, d *database.Db, before time.Time) ([]ExpiredAPIKey, error) {
	q, err := query(d, "deleteExpiredExternalApiKeys")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExpiredAPIKey
	for rows.Next() {
		var k ExpiredAPIKey
		if err := rows.Scan(&k.AuthType, &k.KeyHash); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}
