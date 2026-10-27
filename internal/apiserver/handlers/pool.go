package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/sandbox/config"
	"github.com/NodeOps-app/sandbox/internal/apiserver/metrics"
	"github.com/NodeOps-app/sandbox/internal/audit"
	"github.com/NodeOps-app/sandbox/internal/hostrpc"
	"github.com/NodeOps-app/sandbox/internal/hosts/api"
	"github.com/NodeOps-app/sandbox/internal/hosts/vm"
	"github.com/NodeOps-app/sandbox/internal/httpx"
	"github.com/NodeOps-app/sandbox/internal/proto"
	schedapi "github.com/NodeOps-app/sandbox/internal/scheduler/api"
	"github.com/NodeOps-app/sandbox/internal/utils"
	"github.com/NodeOps-app/sandbox/models"
)

// matchesPool is strict on purpose: a pool VM is a bare box, so any
// personalization field must send the request to the normal create
// path where those fields can actually be applied.
func matchesPool(cfg config.PoolConfig, req *proto.CreateReq) bool {
	if !cfg.Enabled {
		return false
	}
	spec := cfg.Spec
	if req.Shape != spec.Shape {
		return false
	}
	if req.DiskMib != 0 && req.DiskMib != spec.DiskMib {
		return false
	}
	if req.Rootfs != nil && *req.Rootfs != spec.Rootfs {
		return false
	}
	if len(req.SSHPubkeys) > 0 {
		return false
	}
	if len(req.Envs) > 0 {
		return false
	}
	if len(req.Labels) > 0 {
		return false
	}
	if len(req.Egress) > 0 {
		return false
	}
	if len(req.Disks) > 0 {
		return false
	}
	if len(req.Networks) > 0 {
		return false
	}
	if req.HostID != "" {
		return false
	}
	if len(req.NodeSelector) > 0 {
		return false
	}
	if req.Name != nil {
		return false
	}
	if req.AutoPauseAfterSeconds != nil {
		return false
	}
	if req.IngressEnabled != nil && *req.IngressEnabled {
		return false
	}
	return true
}

// tryClaimFromPool returns (sb, nil) on hit, (nil, nil) on miss
// (ineligible or empty), (nil, err) on tx failure. The owner UPDATE
// and audit INSERT commit atomically — if audit emit fails the tx
// rolls back, the row goes back to created_by=pool, and the caller
// falls through to normal create.
func (h *Handler) tryClaimFromPool(ctx context.Context, c *fiber.Ctx, req *proto.CreateReq, userID string) (*models.Sandbox, error) {
	if !matchesPool(h.pool, req) {
		metrics.PoolClaimTotal.WithLabelValues("miss_ineligible").Inc()
		return nil, nil
	}

	// Batched claim path. The audit context + is_internal flag must be
	// captured here on the request goroutine — the batcher worker has no
	// *fiber.Ctx. nil batcher = inline fallback. PoolClaimTotal is
	// counted inside the batcher; PoolClaimSeconds is observed here to
	// cover the same window (incl. batch queue wait) as the inline path.
	if h.claimBatcher != nil {
		t0 := time.Now()
		ac := h.auditCtxWithSubject(c, "sandbox", "")
		isInternal := utils.IsInternalFromContext(c.UserContext())
		sb, err := h.claimBatcher.submit(ctx, userID, ac, isInternal)
		if err == nil {
			outcome := "miss_empty"
			if sb != nil {
				outcome = "hit"
			}
			metrics.PoolClaimSeconds.WithLabelValues(outcome).Observe(time.Since(t0).Seconds())
		}
		return sb, err
	}

	t0 := time.Now()

	tx, err := h.repo.DB.Con.Begin(ctx)
	if err != nil {
		metrics.PoolClaimTotal.WithLabelValues("error").Inc()
		return nil, err
	}
	tBegin := time.Now()
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit

	sb, err := models.ClaimPoolSandboxTx(ctx, tx, h.repo.DB, models.ClaimPoolParams{
		NewOwnerID: userID,
		Region:     h.region,
		Shape:      h.pool.Spec.Shape,
		DiskMib:    h.pool.Spec.DiskMib,
		Rootfs:     h.pool.Spec.Rootfs,
	})
	tClaim := time.Now()
	if err != nil {
		metrics.PoolClaimTotal.WithLabelValues("error").Inc()
		return nil, err
	}
	if sb == nil {
		metrics.PoolClaimTotal.WithLabelValues("miss_empty").Inc()
		metrics.PoolClaimSeconds.WithLabelValues("miss_empty").Observe(time.Since(t0).Seconds())
		return nil, nil
	}

	if err := h.audit.EmitInTx(ctx, tx,
		h.auditCtxWithSubject(c, "sandbox", sb.ID),
		audit.ActionSandboxCreate,
		audit.OperationCreate,
		audit.BuildSandboxCreate(sb),
	); err != nil {
		metrics.PoolClaimTotal.WithLabelValues("error").Inc()
		return nil, err
	}
	tAudit := time.Now()

	if err := tx.Commit(ctx); err != nil {
		metrics.PoolClaimTotal.WithLabelValues("error").Inc()
		return nil, err
	}
	tCommit := time.Now()

	metrics.PoolClaimTotal.WithLabelValues("hit").Inc()
	metrics.PoolClaimSeconds.WithLabelValues("hit").Observe(time.Since(t0).Seconds())
	// Prewarm's sandbox.running was suppressed by the pool-user guard;
	// emit one now so billing sees the tenant's usage interval start.
	h.emitBillingEvent(ctx, sb.ID, models.BillingEventSandboxRunning, string(models.StatusCreating))
	tBilling := time.Now()

	// Per-stage burst diagnostics — log EVERY claim so we can build a
	// real histogram of where the ~14ms p50 / ~88ms p99 pool stage
	// spends its time under N=100. Previously threshold-gated at
	// >100ms; nothing fires under normal traffic. One-line per claim,
	// stage deltas in ms.
	log.WithContext(ctx).Infof("[pool-claim-stages] sb=%s total=%dms begin=%dms claim=%dms audit=%dms commit=%dms billing=%dms",
		sb.ID,
		tBilling.Sub(t0).Milliseconds(),
		tBegin.Sub(t0).Milliseconds(),
		tClaim.Sub(tBegin).Milliseconds(),
		tAudit.Sub(tClaim).Milliseconds(),
		tCommit.Sub(tAudit).Milliseconds(),
		tBilling.Sub(tCommit).Milliseconds(),
	)

	// Bump guest clock so the tenant's first SigV4 request doesn't skew.
	go h.kickPoolClaim(sb)
	return sb, nil
}

// kickPoolClaim POSTs to the owning host's /v1/internal/sandboxes/:id/pool-claim-kick.
// Fire-and-forget; runs in its own goroutine so the create response returns fast.
func (h *Handler) kickPoolClaim(sb *models.Sandbox) {
	if sb.HostID == nil || *sb.HostID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	host, err := h.repo.GetHost(ctx, *sb.HostID)
	if err != nil || host == nil {
		log.Warnf("[pool] kick lookup host=%s: %v", *sb.HostID, err)
		return
	}
	h.kickPoolClaimTo(sb, host)
}

// kickPoolClaimTo POSTs the pool-claim kick using an already-resolved host.
// Batch callers resolve each distinct host once and reuse it across every
// claim on that host — otherwise a 100-wide burst issues ~100 GetHost DB
// reads, flooding the connection pool and contending with the claim tx's own
// commit (measured: ~74 active backends + WALWrite/WalSync waits under burst).
// Fire-and-forget; its own detached ctx so the create response returns fast.
func (h *Handler) kickPoolClaimTo(sb *models.Sandbox, host *models.Host) {
	if host == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addr := host.Addr
	if !strings.HasPrefix(addr, "http://") && !strings.HasPrefix(addr, "https://") {
		addr = h.hostScheme + "://" + addr
	}
	url := strings.TrimRight(addr, "/") + "/v1/internal/sandboxes/" + sb.ID + "/pool-claim-kick"
	// Pass the new owner so the host can seed its in-memory ownership
	// cache (sb.CreatedBy) synchronously with the kick. Without this the
	// first tenant exec always eats a DB round-trip. Only applied host-
	// side when the current cached value is still "pool" — the kick
	// never overwrites a legitimate tenant owner.
	body := strings.NewReader(fmt.Sprintf(`{"owner":%q}`, sb.CreatedBy))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.http.Do(req)
	if err != nil {
		log.Warnf("[pool] kick host=%s sb=%s: %v", host.ID, sb.ID, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		log.Warnf("[pool] kick host=%s sb=%s: %d", host.ID, sb.ID, resp.StatusCode)
	}
}

// respondPoolCreated mirrors the wire shape the host returns via the
// normal forward path so SDK clients can't tell a pool hit from a
// cold create.
func (h *Handler) respondPoolCreated(c *fiber.Ctx, sb *models.Sandbox) error {
	ip := ""
	if sb.IP != nil {
		ip = *sb.IP
	}
	resp := proto.CreateResp{
		ID:                  sb.ID,
		Status:              string(models.StatusRunning),
		Name:                sb.Name,
		Labels:              sb.Labels,
		IP:                  ip,
		Shape:               sb.Shape,
		Rootfs:              sb.Rootfs,
		VCPU:                sb.VCPU,
		MemMib:              sb.MemMib,
		DiskMib:             sb.DiskMib,
		SpawnMs:             sb.SpawnMs,
		Egress:              sb.Egress,
		BandwidthQuotaBytes: sb.BandwidthQuotaBytes,
	}
	if sb.IngressEnabled && h.ingressDomainSuffix != "" {
		resp.IngressURLTemplate = h.ingressURLTemplate(sb.ID)
	}
	return httpx.Success(c, resp)
}

// SpawnPoolSandbox is the grow-loop's create hook. Same scheduler +
// forward flow as user creates, minus auth, quota, and audit. On any
// failure after INSERT commits, the row is marked failed so the
// scheduler's next hydrate drops it from capacity SUMs.
func (h *Handler) SpawnPoolSandbox(ctx context.Context) (string, error) {
	if !h.pool.Enabled {
		return "", fmt.Errorf("pool disabled")
	}
	spec := h.pool.Spec

	shapeCat := h.shapes.Shapes(ctx)
	var schedMem, schedVCPU int
	var schedDefaultDisk int64
	for _, sh := range shapeCat {
		if sh.ID == spec.Shape {
			schedMem = sh.MemMib
			schedVCPU = sh.VCPU
			schedDefaultDisk = sh.DefaultDisk
			break
		}
	}
	if schedMem == 0 {
		return "", fmt.Errorf("pool spec shape %q not in catalog", spec.Shape)
	}
	schedDisk := schedDefaultDisk
	if spec.DiskMib > 0 {
		schedDisk = spec.DiskMib
	}

	sbID := vm.NewSandboxID()
	now := time.Now().UTC()
	var rootfsPtr *string
	if spec.Rootfs != "" {
		r := spec.Rootfs
		rootfsPtr = &r
	}
	rec := models.Sandbox{
		ID:                  sbID,
		Status:              models.StatusCreating,
		Shape:               spec.Shape,
		Rootfs:              rootfsPtr,
		MemMib:              schedMem,
		VCPU:                schedVCPU,
		DiskMib:             schedDisk,
		CreatedAt:           now,
		CreatedBy:           h.pool.OwnerID,
		Region:              h.region,
		BandwidthQuotaBytes: h.defaultBandwidthQuotaBytes,
	}
	name, status, fail := h.insertSandboxWithName(ctx, rec, "")
	if status != 0 {
		return "", fmt.Errorf("insert pool sandbox row: status=%d fail=%q", status, fail)
	}
	rec.Name = &name

	resp, err := h.schedulerClient.Schedule(ctx, schedapi.ScheduleRequest{
		SandboxID: sbID,
		Shape:     spec.Shape,
		Rootfs:    spec.Rootfs,
		MemMiB:    schedMem,
		VCPU:      schedVCPU,
		DiskMiB:   schedDisk,
		Region:    h.region,
	})
	if err != nil {
		schedMsg := "schedule failed: " + err.Error()
		_ = h.repo.MarkFailed(ctx, sbID, &schedMsg, time.Now().UTC(), h.billingEmitter)
		return "", err
	}
	respHostID := resp.HostID
	if err := h.repo.SetSandboxHost(ctx, sbID, &respHostID); err != nil {
		setHostMsg := "set host failed: " + err.Error()
		_ = h.repo.MarkFailed(ctx, sbID, &setHostMsg, time.Now().UTC(), h.billingEmitter)
		return "", err
	}

	body := api.CreateReq{
		Shape:               spec.Shape,
		Rootfs:              rootfsPtr,
		DiskMib:             schedDisk,
		Name:                &name,
		Region:              h.region,
		BandwidthQuotaBytes: h.defaultBandwidthQuotaBytes,
	}
	buf, err := json.Marshal(body)
	if err != nil {
		failMsg := "marshal pool create body"
		_ = h.repo.MarkFailed(ctx, sbID, &failMsg, time.Now().UTC(), h.billingEmitter)
		return "", err
	}
	if err := postPoolCreateToHost(ctx, resp.HostAddr, sbID, h.pool.OwnerID, buf, h.http); err != nil {
		fwdMsg := "forward failed: " + err.Error()
		_ = h.repo.MarkFailed(ctx, sbID, &fwdMsg, time.Now().UTC(), h.billingEmitter)
		return "", err
	}
	return sbID, nil
}

func postPoolCreateToHost(ctx context.Context, hostAddr, sbID, createdBy string, body []byte, client *http.Client) error {
	addr := hostAddr
	if !strings.HasPrefix(addr, "http://") && !strings.HasPrefix(addr, "https://") {
		addr = hostScheme() + "://" + addr
	}
	url := strings.TrimRight(addr, "/") + "/v1/sandboxes"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(proto.HeaderSandboxID, sbID)
	httpx.SetRequestIDHeader(ctx, req)
	if createdBy != "" {
		utils.SetUserIDHeader(req, createdBy)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("host returned %d: %s", resp.StatusCode, string(buf))
	}
	return nil
}

// DestroyPoolSandbox is the shrink-loop's destroy hook. Idempotent on
// terminal rows and guards against ever tearing down a user-owned row
// (belt against a shrink-loop bug).
func (h *Handler) DestroyPoolSandbox(ctx context.Context, sandboxID string) error {
	rec, err := h.repo.Get(ctx, sandboxID)
	if err != nil {
		return err
	}
	if rec == nil {
		return fmt.Errorf("pool sandbox %s not found", sandboxID)
	}
	if rec.CreatedBy != h.pool.OwnerID {
		return fmt.Errorf("sandbox %s not owned by pool (created_by=%q)", sandboxID, rec.CreatedBy)
	}
	if rec.Status == models.StatusDestroyed || rec.Status == models.StatusFailed {
		return nil
	}
	status, err := h.repo.MarkPoolDestroying(ctx, sandboxID, h.pool.OwnerID)
	if err != nil {
		return err
	}
	// A concurrent claim or another shrink won; do not call the host.
	if status == "" {
		return nil
	}
	if rec.HostID == nil || *rec.HostID == "" {
		return nil
	}
	host, err := h.repo.GetHost(ctx, *rec.HostID)
	if err != nil || host == nil {
		return err
	}
	response, err := hostrpc.Destroy(ctx, h.http, *host, sandboxID, rec.CreatedBy)
	if err != nil {
		log.WithContext(ctx).Warnf("[pool] eager DestroyOnHost(host=%s sb=%s): %v (reconcile will retry)", host.ID, sandboxID, err)
	} else {
		defer response.Body.Close()
		if !hostrpc.DestroyAccepted(response) {
			log.WithContext(ctx).Warnf("[pool] eager DestroyOnHost(host=%s sb=%s): status=%d (reconcile will retry)", host.ID, sandboxID, response.StatusCode)
		}
	}
	return nil
}
