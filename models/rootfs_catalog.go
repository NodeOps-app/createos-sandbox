package models

import (
	"context"
	"errors"
	"time"

	"github.com/NodeOps-app/sandbox/database"

	"github.com/jackc/pgx/v5"
)

// RootfsCatalog is one row of rootfs_catalog (mirror of
// store.RootfsCatalogRecord). Cluster-wide metadata the control plane
// consults at create/list time.
type RootfsCatalog struct {
	Name        string    `json:"name" sql:"name"`
	Description *string   `json:"description,omitempty" sql:"description"`
	Disabled    bool      `json:"disabled" sql:"disabled"`
	Deprecated  bool      `json:"deprecated" sql:"deprecated"`
	Successor   *string   `json:"successor,omitempty" sql:"successor"`
	CreatedAt   time.Time `json:"created_at" sql:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" sql:"updated_at"`
}

func GetRootfsMetadata(ctx context.Context, d *database.Db, name string) (*RootfsCatalog, error) {
	q, err := query(d, "getRootfsCatalog")
	if err != nil {
		return nil, err
	}
	row := d.Con.QueryRow(ctx, q, name)
	var rec RootfsCatalog
	err = row.Scan(&rec.Name, &rec.Description, &rec.Disabled, &rec.Deprecated, &rec.Successor, &rec.CreatedAt, &rec.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func ListRootfsMetadata(ctx context.Context, d *database.Db) ([]RootfsCatalog, error) {
	q, err := query(d, "listRootfsCatalog")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RootfsCatalog
	for rows.Next() {
		var rec RootfsCatalog
		if err := rows.Scan(&rec.Name, &rec.Description, &rec.Disabled, &rec.Deprecated, &rec.Successor, &rec.CreatedAt, &rec.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}
