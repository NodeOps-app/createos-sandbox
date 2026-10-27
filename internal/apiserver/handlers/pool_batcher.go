package handlers

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/sandbox/internal/apiserver/metrics"
	"github.com/NodeOps-app/sandbox/internal/audit"
	"github.com/NodeOps-app/sandbox/internal/utils"
	"github.com/NodeOps-app/sandbox/models"
)

// poolClaimBatchEnabled toggles the batched claim path at compile time.
// Set false to fall back to the per-request inline claim.
const poolClaimBatchEnabled = true

// maxClaimBatch caps how many claims one batch transaction coalesces.
const maxClaimBatch = 128

// poolClaimBatcher coalesces concurrent pool claims into one DB
// transaction. Every request reaching it already matched the pool spec
// (matchesPool in tryClaimFromPool), so all draw from the same bucket
// and can be claimed together. One worker blocks on the first request,
// drains everything else already queued, and applies the set in one tx:
// under burst this forms large batches, under light load size-1.
type poolClaimBatcher struct {
	h    *Handler
	reqs chan claimReq
}

type claimReq struct {
	owner string
	// auditCx and isInternal are captured on the request goroutine
	// because the batcher's tx runs on a detached context with neither
	// the fiber ctx (audit needs IP/UA/token) nor the is_internal flag
	// (billing's fast-path skip reads it off the context).
	auditCx    audit.Context
	isInternal bool
	resp       chan claimResult
}

type claimResult struct {
	sb  *models.Sandbox
	err error
}

func newPoolClaimBatcher(h *Handler) *poolClaimBatcher {
	b := &poolClaimBatcher{h: h, reqs: make(chan claimReq, 1024)}
	go b.run()
	return b
}

// submit blocks until the claim's batch has been applied. Returns
// (sb, nil) on a hit, (nil, nil) on a miss (partial fill / empty pool),
// (nil, err) on tx failure.
func (b *poolClaimBatcher) submit(ctx context.Context, owner string, ac audit.Context, isInternal bool) (*models.Sandbox, error) {
	r := claimReq{owner: owner, auditCx: ac, isInternal: isInternal, resp: make(chan claimResult, 1)}
	select {
	case b.reqs <- r:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case res := <-r.resp:
		return res.sb, res.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (b *poolClaimBatcher) run() {
	for {
		first, ok := <-b.reqs
		if !ok {
			return
		}
		batch := []claimReq{first}
	drain:
		for len(batch) < maxClaimBatch {
			select {
			case r, ok := <-b.reqs:
				if !ok {
					break drain
				}
				batch = append(batch, r)
			default:
				break drain
			}
		}
		b.apply(batch)
	}
}

func failAll(batch []claimReq, err error) {
	for _, r := range batch {
		r.resp <- claimResult{err: err}
	}
}

func (b *poolClaimBatcher) apply(batch []claimReq) {
	// Detached context: one caller's cancelled request must not abort
	// the shared tx for the whole batch.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	owners := make([]string, len(batch))
	for i, r := range batch {
		owners[i] = r.owner
	}

	tx, err := b.h.repo.DB.Con.Begin(ctx)
	if err != nil {
		for range batch {
			metrics.PoolClaimTotal.WithLabelValues("error").Inc()
		}
		failAll(batch, err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	spec := b.h.pool.Spec
	sbs, err := models.ClaimPoolSandboxBatchTx(ctx, tx, b.h.repo.DB, b.h.region, spec.Shape, spec.DiskMib, spec.Rootfs, owners)
	if err != nil {
		for range batch {
			metrics.PoolClaimTotal.WithLabelValues("error").Inc()
		}
		failAll(batch, err)
		return
	}

	// Each claimed row's CreatedBy is the owner the SQL assigned it;
	// group by owner and hand out in order so duplicate owners (one user
	// firing a burst) each get a distinct row. assigned[i] is the sb for
	// batch[i], or nil on a partial fill.
	byOwner := make(map[string][]*models.Sandbox, len(sbs))
	for _, sb := range sbs {
		byOwner[sb.CreatedBy] = append(byOwner[sb.CreatedBy], sb)
	}
	assigned := make([]*models.Sandbox, len(batch))
	cursor := make(map[string]int, len(byOwner))
	for i, r := range batch {
		rows := byOwner[r.owner]
		idx := cursor[r.owner]
		if idx < len(rows) {
			assigned[i] = rows[idx]
			cursor[r.owner] = idx + 1
		}
	}

	// Audit inside the tx so a failed emit rolls the claim back (rows
	// return to the pool, requests fall through to cold create).
	for i, sb := range assigned {
		if sb == nil {
			continue
		}
		ac := batch[i].auditCx
		ac.SubjectType = "sandbox"
		ac.SubjectID = sb.ID
		if err := b.h.audit.EmitInTx(ctx, tx, ac,
			audit.ActionSandboxCreate, audit.OperationCreate,
			audit.BuildSandboxCreate(sb),
		); err != nil {
			for range batch {
				metrics.PoolClaimTotal.WithLabelValues("error").Inc()
			}
			failAll(batch, err)
			return
		}
	}

	if err := tx.Commit(ctx); err != nil {
		for range batch {
			metrics.PoolClaimTotal.WithLabelValues("error").Inc()
		}
		failAll(batch, err)
		return
	}

	log.Infof("[pool-claim-batch] batch=%d claimed=%d", len(batch), len(sbs))

	// Resolve each DISTINCT host once, up front — not per-claim inside the
	// kick. A 100-wide burst otherwise fires ~100 GetHost DB reads (for ~5
	// hosts), flooding the connection pool and contending with this tx's own
	// commit (measured: ~74 active backends + WALWrite/WalSync waits). One
	// lookup per host collapses that to ~5.
	hostByID := make(map[string]*models.Host)
	for _, sb := range assigned {
		if sb == nil || sb.HostID == nil || *sb.HostID == "" {
			continue
		}
		if _, ok := hostByID[*sb.HostID]; ok {
			continue
		}
		hctx, hcancel := context.WithTimeout(context.Background(), 3*time.Second)
		host, err := b.h.repo.GetHost(hctx, *sb.HostID)
		hcancel()
		if err != nil || host == nil {
			log.Warnf("[pool-claim-batch] kick lookup host=%s: %v", *sb.HostID, err)
			continue
		}
		hostByID[*sb.HostID] = host
	}

	for i, r := range batch {
		sb := assigned[i]
		if sb == nil {
			metrics.PoolClaimTotal.WithLabelValues("miss_empty").Inc()
			r.resp <- claimResult{sb: nil}
			continue
		}
		metrics.PoolClaimTotal.WithLabelValues("hit").Inc()
		// Re-stamp is_internal so emitBillingEvent's internal-skip
		// fast-path fires (the detached ctx lost it).
		billingCtx := utils.WithIsInternal(ctx, r.isInternal)
		b.h.emitBillingEvent(billingCtx, sb.ID, models.BillingEventSandboxRunning, string(models.StatusCreating))
		if sb.HostID != nil {
			if host := hostByID[*sb.HostID]; host != nil {
				go b.h.kickPoolClaimTo(sb, host)
			}
		}
		r.resp <- claimResult{sb: sb}
	}
}
