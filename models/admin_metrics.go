package models

import (
	"context"
	"encoding/json"
	"time"
)

// AdminUsage contains aggregate sandbox and audit activity, with an optional
// display email for a selected user; no request metadata, credentials, or failure details. Replicated rows are read once from
// the local database rather than summing counts from regional peers.
type AdminUsage struct {
	Events          int64           `json:"events"`
	Accounts        int64           `json:"accounts"`
	SandboxCreates  int64           `json:"sandbox_creates"`
	Days            []AdminUsageDay `json:"days"`
	UserEmail       string          `json:"user_email,omitempty"`
	FirstRecordedAt *time.Time      `json:"first_recorded_at"`
}
type AdminUsageDay struct {
	Day            string `json:"day"`
	Events         int64  `json:"events"`
	Accounts       int64  `json:"accounts"`
	SandboxCreates int64  `json:"sandbox_creates"`
}
type AdminFeatureUsage struct {
	Action   string            `json:"action"`
	Events   int64             `json:"events"`
	Accounts int64             `json:"accounts"`
	Days     []AdminFeatureDay `json:"days"`
}
type AdminFeatureDay struct {
	Day    string `json:"day"`
	Events int64  `json:"events"`
}

func (r *Repo) GetAdminUsage(ctx context.Context, from, to time.Time, actions []string, bucket, userID, region string) (AdminUsage, error) {
	out := AdminUsage{Days: []AdminUsageDay{}}
	q, err := query(r.DB, "getAdminUsage")
	if err != nil {
		return out, err
	}
	var days []byte
	err = r.DB.Con.QueryRow(ctx, q, from, to, actions, bucket, userID, region).Scan(&out.Events, &out.Accounts, &out.SandboxCreates, &days, &out.FirstRecordedAt)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(days, &out.Days)
	return out, err
}
func (r *Repo) GetAdminFeatureUsage(ctx context.Context, from, to time.Time, actions []string, bucket, userID, region string) ([]AdminFeatureUsage, error) {
	out := []AdminFeatureUsage{}
	q, err := query(r.DB, "getAdminFeatureUsage")
	if err != nil {
		return nil, err
	}
	rows, err := r.DB.Con.Query(ctx, q, from, to, actions, bucket, userID, region)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var v AdminFeatureUsage
		var days []byte
		if err := rows.Scan(&v.Action, &v.Events, &v.Accounts, &days); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(days, &v.Days); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

type AdminUsageGroup struct {
	Email          string `json:"email,omitempty"`
	ID             string `json:"id"`
	SandboxCreates int64  `json:"sandbox_creates"`
	Events         int64  `json:"events"`
	Accounts       int64  `json:"accounts"`
}

func (r *Repo) GetAdminUsageGroups(ctx context.Context, from, to time.Time, actions []string, byRegion, excludeInternal bool, limit, offset int) ([]AdminUsageGroup, error) {
	name := "getAdminUserUsage"
	if byRegion {
		name = "getAdminRegionUsage"
	}
	q, err := query(r.DB, name)
	if err != nil {
		return nil, err
	}
	args := []any{from, to, actions, limit, offset}
	if !byRegion {
		args = append(args, excludeInternal)
	}
	rows, err := r.DB.Con.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AdminUsageGroup{}
	for rows.Next() {
		var v AdminUsageGroup
		if err := rows.Scan(&v.ID, &v.SandboxCreates, &v.Events, &v.Accounts); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// AdminActivity deliberately omits event metadata, IPs, credentials and errors.
type AdminActivity struct {
	UserEmail  string    `json:"user_email,omitempty"`
	ID         string    `json:"id"`
	OccurredAt time.Time `json:"occurred_at"`
	Action     string    `json:"action"`
	UserID     string    `json:"user_id"`
	Region     string    `json:"region"`
	ResourceID string    `json:"resource_id"`
}

// Current states are independent of the activity window and exclude unclaimed pool VMs.
type AdminLiveCounts struct {
	Running int64 `json:"running"`
	Paused  int64 `json:"paused"`
}

func (r *Repo) GetAdminLiveCounts(ctx context.Context, userID, region string) (AdminLiveCounts, error) {
	var out AdminLiveCounts
	q, err := query(r.DB, "getAdminLiveCounts")
	if err != nil {
		return out, err
	}
	err = r.DB.Con.QueryRow(ctx, q, userID, region).Scan(&out.Running, &out.Paused)
	return out, err
}

func (r *Repo) GetAdminActivity(ctx context.Context, from, to time.Time, userID, region string, actions []string) ([]AdminActivity, error) {
	q, err := query(r.DB, "getAdminActivity")
	if err != nil {
		return nil, err
	}
	rows, err := r.DB.Con.Query(ctx, q, from, to, userID, region, actions)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AdminActivity{}
	for rows.Next() {
		var v AdminActivity
		if err := rows.Scan(&v.ID, &v.OccurredAt, &v.Action, &v.UserID, &v.Region, &v.ResourceID); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// AdminSizingUsage counts creations by their stored allocation, not utilization.
type AdminSizingUsage struct {
	Dimension string           `json:"dimension"`
	Value     string           `json:"value"`
	Count     int64            `json:"count"`
	Days      []AdminSizingDay `json:"days"`
}

type AdminSizingDay struct {
	Day   string `json:"day"`
	Count int64  `json:"count"`
}

func (r *Repo) GetAdminSizingUsage(ctx context.Context, from, to time.Time, bucket, userID, region string) ([]AdminSizingUsage, error) {
	q, err := query(r.DB, "getAdminSizingUsage")
	if err != nil {
		return nil, err
	}
	rows, err := r.DB.Con.Query(ctx, q, from, to, bucket, userID, region)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AdminSizingUsage{}
	for rows.Next() {
		var row AdminSizingUsage
		var days []byte
		if err := rows.Scan(&row.Dimension, &row.Value, &row.Count, &days); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(days, &row.Days); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
