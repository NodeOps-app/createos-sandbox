package models

import (
	"context"
	"errors"
	"time"

	"github.com/NodeOps-app/sandbox/database"

	"github.com/jackc/pgx/v5"
)

// TemplateIDPrefix is the canonical prefix for `templates.id`.
const TemplateIDPrefix = "tpl_"

// TemplateStatus is the templates.status enum.
type TemplateStatus string

const (
	TemplateStatusPending  TemplateStatus = "pending"  // queued, awaiting builder claim
	TemplateStatusBuilding TemplateStatus = "building" // builder claimed; sandbox build in flight
	TemplateStatusReady    TemplateStatus = "ready"    // ext4 in R2; sandboxes can spawn from this
	TemplateStatusFailed   TemplateStatus = "failed"   // build failed; logs in ClickHouse
)

// Template is one row of the templates table (mirror of store.TemplateRecord).
type Template struct {
	ID            string         `json:"id" sql:"id"`
	UserID        string         `json:"user_id" sql:"user_id"`
	Name          string         `json:"name" sql:"name"`
	Base          string         `json:"base" sql:"base"`
	Status        TemplateStatus `json:"status" sql:"status"`
	Dockerfile    string         `json:"dockerfile" sql:"dockerfile"`
	SizeBytes     int64          `json:"size_bytes" sql:"size_bytes"`
	Ext4SizeBytes int64          `json:"ext4_size_bytes" sql:"ext4_size_bytes"`
	SHA256        *string        `json:"sha256,omitempty" sql:"sha256"`
	CreatedAt     time.Time      `json:"created_at" sql:"created_at"`
	BuiltAt       *time.Time     `json:"built_at,omitempty" sql:"built_at"`
	DeletedAt     *time.Time     `json:"deleted_at,omitempty" sql:"deleted_at"`
	Attempts      int            `json:"attempts" sql:"attempts"` // claim count; janitor uses this to give up after N
}

func InsertTemplate(ctx context.Context, d *database.Db, t Template) error {
	q, err := query(d, "insertTemplate")
	if err != nil {
		return err
	}
	_, err = d.Con.Exec(ctx, q, t.ID, t.UserID, t.Name, t.Base, t.Dockerfile)
	return err
}

func GetTemplate(ctx context.Context, d *database.Db, id string) (*Template, error) {
	q, err := query(d, "getTemplate")
	if err != nil {
		return nil, err
	}
	row := d.Con.QueryRow(ctx, q, id)
	var t Template
	var status string
	if err := row.Scan(&t.ID, &t.UserID, &t.Name, &t.Base, &status, &t.Dockerfile,
		&t.SizeBytes, &t.Ext4SizeBytes, &t.SHA256,
		&t.CreatedAt, &t.BuiltAt, &t.DeletedAt, &t.Attempts); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	t.Status = TemplateStatus(status)
	return &t, nil
}

func GetLatestReadyByName(ctx context.Context, d *database.Db, userID, name string) (string, error) {
	q, err := query(d, "getLatestReadyByName")
	if err != nil {
		return "", err
	}
	var id string
	if err := d.Con.QueryRow(ctx, q, userID, name).Scan(&id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return id, nil
}

func ListUserTemplates(ctx context.Context, d *database.Db, userID string, limit, offset int) ([]Template, error) {
	q, err := query(d, "listUserTemplates")
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := d.Con.Query(ctx, q, userID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Template
	for rows.Next() {
		var t Template
		var status string
		if err := rows.Scan(&t.ID, &t.UserID, &t.Name, &t.Base, &status, &t.Dockerfile,
			&t.SizeBytes, &t.Ext4SizeBytes, &t.SHA256,
			&t.CreatedAt, &t.BuiltAt, &t.DeletedAt, &t.Attempts); err != nil {
			return nil, err
		}
		t.Status = TemplateStatus(status)
		out = append(out, t)
	}
	return out, rows.Err()
}

// CountUserTemplates returns the total number of non-deleted templates
// the user owns (any status). Drives pagination.total on
// GET /v1/templates.
func CountUserTemplates(ctx context.Context, d *database.Db, userID string) (int, error) {
	q, err := query(d, "countUserTemplates")
	if err != nil {
		return 0, err
	}
	var n int
	if err := d.Con.QueryRow(ctx, q, userID).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func CountInflightTemplatesForUser(ctx context.Context, d *database.Db, userID string) (int, error) {
	q, err := query(d, "countInflightForUser")
	if err != nil {
		return 0, err
	}
	var n int
	if err := d.Con.QueryRow(ctx, q, userID).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func TemplateNameTaken(ctx context.Context, d *database.Db, userID, name string) (bool, error) {
	q, err := query(d, "templateNameTaken")
	if err != nil {
		return false, err
	}
	var taken bool
	if err := d.Con.QueryRow(ctx, q, userID, name).Scan(&taken); err != nil {
		return false, err
	}
	return taken, nil
}

func SoftDeleteTemplate(ctx context.Context, d *database.Db, id, userID string) (string, error) {
	q, err := query(d, "softDeleteTemplate")
	if err != nil {
		return "", err
	}
	return scanCASStatus(d.Con.QueryRow(ctx, q, id, userID))
}

func ClaimNextBuild(ctx context.Context, d *database.Db, blockedUsers []string) (*Template, error) {
	q, err := query(d, "claimNextBuild")
	if err != nil {
		return nil, err
	}
	if blockedUsers == nil {
		blockedUsers = []string{}
	}
	row := d.Con.QueryRow(ctx, q, blockedUsers)
	var t Template
	t.Status = TemplateStatusBuilding
	if err := row.Scan(&t.ID, &t.UserID, &t.Name, &t.Base, &t.Dockerfile, &t.CreatedAt, &t.Attempts); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, pgx.ErrNoRows
		}
		return nil, err
	}
	return &t, nil
}

func CompleteTemplateBuild(ctx context.Context, d *database.Db, id string, newStatus TemplateStatus,
	sha256 *string, sizeBytes, ext4SizeBytes int64,
) (string, error) {
	q, err := query(d, "completeTemplateBuild")
	if err != nil {
		return "", err
	}
	return scanCASStatus(d.Con.QueryRow(ctx, q, id, string(newStatus),
		sha256, sizeBytes, ext4SizeBytes))
}

func ReapStuckBuilds(ctx context.Context, d *database.Db, cutoff time.Time) ([]string, error) {
	// Single sweep: every row stuck in `building` past cutoff is marked
	// failed. No retry path — see queries.sql for why.
	q, err := query(d, "reapStuckBuilds")
	if err != nil {
		return nil, err
	}
	rows, err := d.Con.Query(ctx, q, cutoff)
	if err != nil {
		return nil, err
	}
	return scanIDList(rows)
}

func SetTemplateFailed(ctx context.Context, d *database.Db, id string) (string, error) {
	q, err := query(d, "setTemplateFailed")
	if err != nil {
		return "", err
	}
	return scanCASStatus(d.Con.QueryRow(ctx, q, id))
}

func CountTemplatesActive(ctx context.Context, d *database.Db, userID string) (int, error) {
	q, err := query(d, "countTemplatesActive")
	if err != nil {
		return 0, err
	}
	var n int
	return n, d.Con.QueryRow(ctx, q, userID).Scan(&n)
}

func CountTemplatesSince(ctx context.Context, d *database.Db, userID string, since time.Time) (int, error) {
	q, err := query(d, "countTemplatesSince")
	if err != nil {
		return 0, err
	}
	var n int
	return n, d.Con.QueryRow(ctx, q, userID, since).Scan(&n)
}
