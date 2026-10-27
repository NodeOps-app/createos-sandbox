package models

import (
	"context"
	"time"

	"github.com/NodeOps-app/sandbox/database"
)

// HostCachedTemplate is one row of host_cached_templates — the per-host
// ext4 cache state (mirror of store.HostCachedTemplateRecord).
type HostCachedTemplate struct {
	HostID      string     `json:"host_id" sql:"host_id"`
	TplID       string     `json:"tpl_id" sql:"tpl_id"`
	FetchedAt   time.Time  `json:"fetched_at" sql:"fetched_at"`
	LastUsedAt  time.Time  `json:"last_used_at" sql:"last_used_at"`
	CachedUntil *time.Time `json:"cached_until,omitempty" sql:"cached_until"`
}

func UpsertHostCachedTemplate(ctx context.Context, d *database.Db, hostID, tplID string, cachedUntil time.Time) error {
	q, err := query(d, "upsertHostCachedTemplate")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, hostID, tplID, cachedUntil)
	return err
}

func DeleteHostCachedTemplate(ctx context.Context, d *database.Db, hostID, tplID string) error {
	q, err := query(d, "deleteHostCachedTemplate")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, hostID, tplID)
	return err
}

func ListHostCachedTemplates(ctx context.Context, d *database.Db, hostID string) ([]HostCachedTemplate, error) {
	q, err := query(d, "listHostCachedTemplates")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostCachedTemplate
	for rows.Next() {
		var rec HostCachedTemplate
		if err := rows.Scan(&rec.HostID, &rec.TplID, &rec.FetchedAt, &rec.LastUsedAt, &rec.CachedUntil); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func ListHostsForTemplate(ctx context.Context, d *database.Db) ([]HostCachedTemplate, error) {
	q, err := query(d, "listHostsForTemplate")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostCachedTemplate
	for rows.Next() {
		var rec HostCachedTemplate
		if err := rows.Scan(&rec.HostID, &rec.TplID); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func HostCachedTemplateHasActiveSandbox(ctx context.Context, d *database.Db, hostID, tplID string) (int, error) {
	q, err := query(d, "hostCachedTemplateHasActiveSandbox")
	if err != nil {
		return 0, err
	}
	var n int
	if err := d.Con.QueryRow(ctx, q, hostID, tplID).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}
