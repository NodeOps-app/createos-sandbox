package handlers

import (
	"time"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/sandbox/internal/apiserver/middlewares"
	"github.com/NodeOps-app/sandbox/internal/httpx"
)

// BillingReconcileView is what GET /v1/internal/billing/sandboxes/:id
// returns. Same shape as the webhook payload's `sandbox` block plus
// a top-level `status` — billing diffs this against its in-memory view
// to recover from missed events.
type BillingReconcileView struct {
	ID                  string     `json:"id"`
	UserID              string     `json:"user_id"`
	Status              string     `json:"status"`
	Name                string     `json:"name"`
	Shape               string     `json:"shape"`
	CPUMillicores       int        `json:"cpu_millicores"`
	MemMib              int        `json:"mem_mib"`
	DiskMib             int64      `json:"disk_mib"`
	BandwidthQuotaBytes int64      `json:"bandwidth_quota_bytes"`
	BandwidthUsedBytes  int64      `json:"bandwidth_used_bytes"`
	Region              string     `json:"region"`
	CreatedAt           time.Time  `json:"created_at"`
	RunningAt           *time.Time `json:"running_at"`
	PausedAt            *time.Time `json:"paused_at"`
	DestroyedAt         *time.Time `json:"destroyed_at"`
	ForkedFrom          string     `json:"forked_from,omitempty"`
}

// HandleBillingGetSandbox returns the current billing-relevant view of
// a single sandbox. Auth: billing-role JWT (MustBeIssuedBy("billing")).
// No tenant scoping — this is an internal admin endpoint; the billing
// system is trusted to know its own sandbox ids.
//
// Used for drift reconciliation: "I think X is running but missed a
// destroyed event 6h ago" → call this → trust the answer.
func (h *Handler) HandleBillingGetSandbox(c *fiber.Ctx) error {
	id := c.Params(middlewares.ParamSandboxID)
	rec, err := h.repo.Get(c.UserContext(), id)
	if err != nil {
		log.WithContext(c.UserContext()).Errorf("[billing-reconcile] load %s: %v", id, err)
		return httpx.Error(c, fiber.StatusInternalServerError, "internal error")
	}
	if rec == nil {
		return httpx.Fail(c, fiber.StatusNotFound, "sandbox not found")
	}
	return httpx.Success(c, BillingReconcileView{
		ID:                  rec.ID,
		UserID:              rec.CreatedBy,
		Status:              string(rec.Status),
		Name:                derefStringPtr(rec.Name),
		Shape:               rec.Shape,
		CPUMillicores:       h.shapeMillicores(c.UserContext(), rec.Shape, rec.VCPU),
		MemMib:              rec.MemMib,
		DiskMib:             rec.DiskMib,
		BandwidthQuotaBytes: rec.BandwidthQuotaBytes,
		BandwidthUsedBytes:  rec.BandwidthUsedBytes,
		Region:              rec.Region,
		CreatedAt:           rec.CreatedAt,
		RunningAt:           rec.RunningAt,
		PausedAt:            rec.PausedAt,
		DestroyedAt:         rec.DestroyedAt,
		ForkedFrom:          derefStringPtr(rec.ForkedFrom),
	})
}
