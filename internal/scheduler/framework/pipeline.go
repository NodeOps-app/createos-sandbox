package framework

import (
	"context"
	"errors"
	log "github.com/sirupsen/logrus"
	"math/rand/v2"
	"sort"
	"sync/atomic"
	"time"

	"github.com/NodeOps-app/createos-sandbox/models"
)

// Pipeline runs Filter → Score → Reserve. Construct directly or via
// Registry.BuildPipeline.
type Pipeline struct {
	Filters          []Filter
	Scorers          []Scorer
	ScorerWeights    []int // parallel to Scorers; 0 means "use Scorer.Weight()"
	Reserver         Reserver
	lastRejectionLog atomic.Int64
}

type scored struct {
	host  models.Host
	score int
}

// Schedule runs the pipeline against `hosts`. On Reserver ErrConflict, drops
// the offending host and retries. When Pipeline.Reserver is nil, returns the
// best-ranked host without reserving — useful for dry-runs and tests.
//
// sbID identifies the durable sandbox being created or resumed. The reserver
// keys its delta on this id so hydration can reconcile it without a token.
func (p *Pipeline) Schedule(ctx context.Context, sbID string, req *Request, hosts []models.Host) (*Decision, error) {
	candidates := p.filter(req, hosts)
	if len(candidates) == 0 {
		// Soft-fail the ExcludeHosts filter when honouring it would
		// leave the fleet empty. The exclude list comes from prior
		// resume failures on this sandbox; in a single-host fleet (or
		// when every other host is dead) the exclude is terminal even
		// if whatever caused the past failure has since been fixed.
		// One retry without the exclude lets the resume proceed; the
		// host can fail it again and a fresh entry lands in
		// resume_failed_hosts, so we don't lose the audit trail.
		if len(req.ExcludeHosts) > 0 {
			relaxed := *req
			relaxed.ExcludeHosts = nil
			retry := p.filter(&relaxed, hosts)
			if len(retry) > 0 {
				candidates = retry
				req = &relaxed
			}
		}
	}
	if len(candidates) == 0 {
		p.logRejections(ctx, req, hosts)
		return nil, ErrNoCapacity
	}
	preferred, fallback := preferredHostTiers(req, candidates)
	// Operator placement policy takes precedence. Within each policy tier,
	// prefer a complete cached snapshot before scoring equally local hosts.
	// Reservation conflicts still fall through to uncached eligible hosts.
	tiers := make([][]models.Host, 0, 4)
	now := time.Now()
	for _, tier := range [][]models.Host{preferred, fallback} {
		cached, uncached := snapshotHostTiers(req, tier, now)
		tiers = append(tiers, cached, uncached)
	}
	for _, tier := range tiers {
		ranked := p.score(req, tier)
		for len(ranked) > 0 {
			idx := pickMaxRandom(ranked)
			pick := ranked[idx]
			if p.Reserver == nil {
				return &Decision{HostID: pick.host.ID, Score: pick.score}, nil
			}
			err := p.Reserver.Reserve(ctx, sbID, req, &pick.host)
			if err == nil {
				return &Decision{HostID: pick.host.ID, Score: pick.score}, nil
			}
			if !errors.Is(err, ErrConflict) {
				return nil, err
			}
			ranked = append(ranked[:idx], ranked[idx+1:]...)
		}
	}
	return nil, ErrNoCapacity
}

// preferredHostTiers partitions hosts after filtering. Preferred hosts are
// tried as an absolute first tier, independent of scorer weights. If every
// preferred reservation races and conflicts, Schedule continues with the
// fallback tier rather than failing a request that the region can serve.
func preferredHostTiers(req *Request, hosts []models.Host) ([]models.Host, []models.Host) {
	if req == nil || len(req.PreferredHostIDs) == 0 {
		return nil, hosts
	}
	wanted := make(map[string]struct{}, len(req.PreferredHostIDs))
	for _, hostID := range req.PreferredHostIDs {
		if hostID != "" {
			wanted[hostID] = struct{}{}
		}
	}
	preferred := make([]models.Host, 0, len(wanted))
	fallback := make([]models.Host, 0, len(hosts))
	for _, host := range hosts {
		if _, ok := wanted[host.ID]; ok {
			preferred = append(preferred, host)
		} else {
			fallback = append(fallback, host)
		}
	}
	return preferred, fallback
}

func (p *Pipeline) filter(req *Request, hosts []models.Host) []models.Host {
	out := make([]models.Host, 0, len(hosts))
	for i := range hosts {
		h := hosts[i]
		ok := true
		for _, f := range p.Filters {
			pass, _ := f.Filter(req, &h)
			if !pass {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, h)
		}
	}
	return out
}

func (p *Pipeline) score(req *Request, hosts []models.Host) []scored {
	out := make([]scored, len(hosts))
	for i := range hosts {
		h := hosts[i]
		total := 0
		for j, sc := range p.Scorers {
			w := 0
			if j < len(p.ScorerWeights) {
				w = p.ScorerWeights[j]
			}
			if w == 0 {
				w = sc.Weight()
			}
			total += sc.Score(req, &h) * w
		}
		out[i] = scored{host: h, score: total}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].score > out[j].score })
	return out
}

// pickMaxRandom returns the index of one of the entries tied at the highest
// score, chosen uniformly at random. Assumes `ranked` is sorted descending
// by score.
func pickMaxRandom(ranked []scored) int {
	if len(ranked) == 1 {
		return 0
	}
	top := ranked[0].score
	tied := 1
	for i := 1; i < len(ranked); i++ {
		if ranked[i].score != top {
			break
		}
		tied++
	}
	if tied == 1 {
		return 0
	}
	return rand.IntN(tied)
}

func snapshotHostTiers(req *Request, hosts []models.Host, now time.Time) ([]models.Host, []models.Host) {
	if req == nil || req.SnapshotID == "" {
		return nil, hosts
	}
	var cached, uncached []models.Host
	for _, h := range hosts {
		if h.HasCachedSnapshot(req.SnapshotID, now) {
			cached = append(cached, h)
		} else {
			uncached = append(uncached, h)
		}
	}
	return cached, uncached
}

// Report the first rejection per host, at most once a minute per pipeline.
// This includes status and heartbeat age so unavailable hosts are distinguishable
// from resource exhaustion. Never put request labels or credentials in logs.
func (p *Pipeline) logRejections(ctx context.Context, req *Request, hosts []models.Host) {
	now := time.Now()
	last := p.lastRejectionLog.Load()
	if last != 0 && now.UnixNano()-last < int64(time.Minute) {
		return
	}
	if !p.lastRejectionLog.CompareAndSwap(last, now.UnixNano()) {
		return
	}
	log.WithContext(ctx).WithField("host_count", len(hosts)).Warn("[scheduler] no eligible host")
	for i := range hosts {
		h := &hosts[i]
		if h.Region != req.Region {
			continue
		}
		for _, f := range p.Filters {
			if ok, reason := f.Filter(req, h); !ok {
				if f.Name() == "label_selector" {
					reason = "label mismatch"
				}
				log.WithContext(ctx).WithFields(log.Fields{"host_id": h.ID, "filter": f.Name(), "reason": reason, "host_status": h.Status, "last_seen": h.LastSeen, "heartbeat_age": now.Sub(h.LastSeen)}).Warn("[scheduler] host rejected")
				break
			}
		}
	}
}
