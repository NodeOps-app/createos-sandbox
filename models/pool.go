package models

import (
	"context"
	"errors"
	"time"

	"github.com/NodeOps-app/sandbox/database"

	"github.com/jackc/pgx/v5"
)

type ClaimPoolParams struct {
	NewOwnerID string
	Region     string
	Shape      string
	DiskMib    int64
	Rootfs     string // "" matches rows where rootfs IS NULL (COALESCE'd in SQL)
}

// ClaimPoolSandboxTx runs the claim UPDATE inside the caller's tx so the
// owner change and downstream audit/billing emit commit or roll back
// atomically. Returns (nil, nil) when the pool is empty for this spec.
// The SQL uses `FOR UPDATE SKIP LOCKED` + `AND s.created_by='pool'` in
// the UPDATE WHERE so two concurrent claims cannot win the same row.
func ClaimPoolSandboxTx(ctx context.Context, tx pgx.Tx, d *database.Db, p ClaimPoolParams) (*Sandbox, error) {
	q, err := query(d, "claimPoolSandbox")
	if err != nil {
		return nil, err
	}
	row := tx.QueryRow(ctx, q, p.NewOwnerID, p.Region, p.Shape, p.DiskMib, p.Rootfs)
	rec, err := scanSandbox(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return rec, nil
}

// ClaimPoolSandboxBatchTx claims up to len(owners) pool VMs in one
// transaction, assigning owners[i] to the i-th oldest available row.
// Each returned rec.CreatedBy is its assigned owner (the caller maps
// rows→requests by owner). Fewer rows than owners on a partial fill;
// the caller sends the un-filled requests down the cold create path.
func ClaimPoolSandboxBatchTx(ctx context.Context, tx pgx.Tx, d *database.Db, region, shape string, diskMib int64, rootfs string, owners []string) ([]*Sandbox, error) {
	if len(owners) == 0 {
		return nil, nil
	}
	q, err := query(d, "claimPoolSandboxBatch")
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, q, region, shape, diskMib, rootfs, owners)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*Sandbox, 0, len(owners))
	for rows.Next() {
		rec, err := scanSandbox(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func CountPoolDepth(ctx context.Context, d *database.Db, region, shape string, diskMib int64, rootfs string) (int, error) {
	q, err := query(d, "countPoolDepth")
	if err != nil {
		return 0, err
	}
	var n int
	if err := d.Con.QueryRow(ctx, q, region, shape, diskMib, rootfs).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// SelectAgedPoolSandboxes uses FOR UPDATE SKIP LOCKED — callers must
// wrap in a tx and act on the IDs before commit (or accept losing the
// lock at tx end).
func SelectAgedPoolSandboxes(ctx context.Context, tx pgx.Tx, d *database.Db, region string, maxAge time.Duration, limit int) ([]string, error) {
	q, err := query(d, "selectAgedPoolSandboxes")
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, q, region, int64(maxAge.Seconds()), limit)
	if err != nil {
		return nil, err
	}
	return scanIDList(rows)
}

// MarkPoolDestroying atomically checks ownership and claims the row for shrink.
// A user claim that wins first must leave both its sandbox and access token intact.
func (r *Repo) MarkPoolDestroying(ctx context.Context, id, owner string) (string, error) {
	q, err := query(r.DB, "markPoolDestroying")
	if err != nil {
		return "", err
	}
	return scanCASStatus(r.DB.Con.QueryRow(ctx, q, id, owner))
}
