package models

import (
	"context"
	"fmt"

	"github.com/NodeOps-app/createos-sandbox/database"
)

// Shape is one row of the shapes catalog. Mirrors proto.Shape but
// lives here to keep the models package free of an httpx/types import
// (types already imports models, so the reverse would cycle). The
// control plane converts to proto.Shape at the cache layer.
type Shape struct {
	ID          string
	VCPU        int
	MemMib      int
	DefaultDisk int64
	CPUQuotaPct int
}

// ListEnabledShapes returns every non-disabled shape from the catalog
// in id-sorted order. Hot path: called on every control heartbeat from
// hosts; control caches the result with a TTL to avoid hammering the DB.
func ListEnabledShapes(ctx context.Context, d *database.Db) ([]Shape, error) {
	q, err := query(d, "listEnabledShapes")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("listEnabledShapes: %w", err)
	}
	defer rows.Close()
	out := make([]Shape, 0)
	for rows.Next() {
		var s Shape
		if err := rows.Scan(&s.ID, &s.VCPU, &s.MemMib, &s.DefaultDisk, &s.CPUQuotaPct); err != nil {
			return nil, fmt.Errorf("listEnabledShapes scan: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
