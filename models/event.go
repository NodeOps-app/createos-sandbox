package models

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/NodeOps-app/createos-sandbox/database"
)

// Operational event names are shared by all writers. Keep them here rather
// than embedding reason strings in handlers, workers or SQL.
const (
	EventHostHeartbeatStale = "host.heartbeat_stale"
	EventHostRecovered      = "host.recovered"
	EventRetention          = 30 * 24 * time.Hour
)

// Event records an observed transition, not the resource's current state.
// Metadata is explicitly assembled by its writer and must not contain secrets.
// Host transitions are inserted by their mutation queries in the same statement.
type Event struct {
	ID           string          `json:"id"`
	Region       string          `json:"region"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	Severity     string          `json:"severity"`
	Reason       string          `json:"reason"`
	Message      string          `json:"message"`
	Component    string          `json:"component"`
	Metadata     json.RawMessage `json:"metadata"`
	OccurredAt   time.Time       `json:"occurred_at"`
}

// ListResourceEvents is an internal repository lookup. Public exposure requires
// resource ownership authorization in the calling controller.
func ListResourceEvents(ctx context.Context, d *database.Db, region, resourceType, resourceID string, limit int) ([]Event, error) {
	if region == "" || resourceType == "" || resourceID == "" || limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("events: resource scope and limit between 1 and 1000 required")
	}
	q, err := query(d, "listResourceEvents")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, region, resourceType, resourceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Event, 0)
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.Region, &e.ResourceType, &e.ResourceID, &e.Severity, &e.Reason, &e.Message, &e.Component, &e.Metadata, &e.OccurredAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func SweepExpiredEvents(ctx context.Context, d *database.Db, region string, now time.Time) (int64, error) {
	if region == "" {
		return 0, fmt.Errorf("events: region required")
	}
	q, err := query(d, "sweepExpiredEvents")
	if err != nil {
		return 0, err
	}
	tag, err := d.Con.Exec(ctx, q, region, now.Add(-EventRetention))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
