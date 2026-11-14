package models

import (
	"context"
	"time"

	"github.com/NodeOps-app/createos-sandbox/database"

	"github.com/jackc/pgx/v5"
)

const (
	EuropeRegion       = "eu"
	UnitedStatesRegion = "us"
)

// Region is one row of the regions catalog. Disabled regions still exist
// in the table (so existing host/sandbox refs keep resolving) but the
// scheduler rejects new placements there.
type Region struct {
	Name        string     `json:"name" sql:"name"`
	Description *string    `json:"description,omitempty" sql:"description"`
	CountryCode *string    `json:"country_code,omitempty" sql:"country_code"`
	CreatedAt   time.Time  `json:"created_at" sql:"created_at"`
	DisabledAt  *time.Time `json:"disabled_at,omitempty" sql:"disabled_at"`
}

// IsActive returns true if the region is not disabled.
func (r *Region) IsActive() bool { return r != nil && r.DisabledAt == nil }

// GetRegion returns the row or (nil, nil) on miss.
func GetRegion(ctx context.Context, d *database.Db, name string) (*Region, error) {
	q, err := query(d, "getRegion")
	if err != nil {
		return nil, err
	}
	var r Region
	err = d.Con.QueryRow(ctx, q, name).Scan(
		&r.Name, &r.Description, &r.CountryCode, &r.CreatedAt, &r.DisabledAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// ListRegions returns all regions, including disabled.
func ListRegions(ctx context.Context, d *database.Db) ([]Region, error) {
	q, err := query(d, "listRegions")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Region
	for rows.Next() {
		var r Region
		if err := rows.Scan(&r.Name, &r.Description, &r.CountryCode, &r.CreatedAt, &r.DisabledAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// InsertRegion creates a new region. Errors on duplicate name.
func InsertRegion(ctx context.Context, d *database.Db, r Region) error {
	q, err := query(d, "insertRegion")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, r.Name, r.Description, r.CountryCode)
	return err
}

// DisableRegion marks a region disabled (disabled_at = now). Idempotent.
func DisableRegion(ctx context.Context, d *database.Db, name string) error {
	q, err := query(d, "disableRegion")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, name)
	return err
}
