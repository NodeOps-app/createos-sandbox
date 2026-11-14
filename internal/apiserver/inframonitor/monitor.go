// Package inframonitor checks control-plane invariants and sends debounced
// operational alerts.
package inframonitor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/NodeOps-app/createos-sandbox/models"
)

// Monitor polls this node's LOCAL Postgres replication slots and critical
// database security invariants, then POSTs human-readable alerts to the
// configured webhook. Replication checks are
// deliberately local-only: each region's control watches its own outbound
// slots, so the monitor keeps working during the exact cross-region outage it
// exists to catch (a monitor that reached across regions would be blocked by
// the same cross-region partition).
//
// A slot going active=false pages within ~2 polls (~2 min).
//
// Two signals, both bounded to notify within ~5 min:
//   - active=false  → subscriber disconnected. ~2 min.
//   - replay_lag    → subscriber connected but falling behind. Time-based, so
//     it does NOT move with write-rate bursts (benchmarks won't false-alarm).
const (
	// replMonitorInterval is how often we poll.
	replMonitorInterval = 60 * time.Second
	// replAlertAfter is how many consecutive bad polls a slot must show
	// before we alert — smooths over the brief active=false blip a normal
	// subscriber reconnect causes. 2 polls ~= 2 minutes.
	replAlertAfter = 2
	// replMaxReplayLag is the replay-lag ceiling; beyond it the subscriber is
	// falling behind. Time-based (not WAL bytes) so a write burst that spikes
	// retained-WAL but keeps applying promptly won't page.
	replMaxReplayLag = 2 * time.Minute
)

// slotHealth is the per-slot debounce state held across ticks.
type slotHealth struct {
	badPolls int  // consecutive polls where the slot was unhealthy
	alerting bool // an alert has been sent and not yet recovered
}

// Monitor owns infrastructure health polling and alert delivery for one
// control-plane region.
type Monitor struct {
	repo     *models.Repo
	region   string
	alertURL string
}

func New(repo *models.Repo, region, alertURL string) *Monitor {
	return &Monitor{repo: repo, region: region, alertURL: alertURL}
}

// Run monitors until ctx is cancelled. The API server launches it only when
// monitoring is enabled and an alert URL is configured.
func (m *Monitor) Run(ctx context.Context) {
	client := &http.Client{Timeout: 10 * time.Second}
	state := map[string]*slotHealth{}
	networkOwnershipAlerting := false

	ticker := time.NewTicker(replMonitorInterval)
	defer ticker.Stop()

	for {
		m.checkReplSlots(ctx, client, state)
		m.checkNetworkOwnership(ctx, client, &networkOwnershipAlerting)
		select {
		case <-ctx.Done():
			log.WithContext(ctx).Infof("[infra-monitor] stopping: %v", ctx.Err())
			return
		case <-ticker.C:
		}
	}
}

// checkReplSlots polls the replication slots once and drives per-slot alert /
// recovery transitions. Any query error is logged and skipped — a transient DB
// hiccup must not itself page.
//
// replay_lag comes from pg_stat_replication, correlated to the slot by
// application_name (Spock names the walsender after the slot). It is NULL when
// the subscriber is caught up or disconnected; the active flag covers the
// disconnected case.
func (m *Monitor) checkReplSlots(ctx context.Context, client *http.Client, state map[string]*slotHealth) {
	qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	rows, err := m.repo.DB.Con.Query(qctx, `
		SELECT s.slot_name,
		       s.active,
		       COALESCE(EXTRACT(EPOCH FROM r.replay_lag), 0)::float8 AS replay_lag_s
		FROM pg_replication_slots s
		LEFT JOIN pg_stat_replication r ON r.application_name = s.slot_name`)
	if err != nil {
		log.WithContext(ctx).Warnf("[repl-monitor] query replication state: %v", err)
		return
	}
	defer rows.Close()

	maxLagSecs := replMaxReplayLag.Seconds()
	seen := map[string]struct{}{}
	for rows.Next() {
		var (
			slot    string
			active  bool
			lagSecs float64
		)
		if err := rows.Scan(&slot, &active, &lagSecs); err != nil {
			log.WithContext(ctx).Warnf("[repl-monitor] scan slot row: %v", err)
			return
		}
		seen[slot] = struct{}{}

		reason := ""
		if !active {
			reason = "inactive (subscriber not consuming)"
		} else if lagSecs > maxLagSecs {
			reason = fmt.Sprintf("replay lag %.0fs exceeds %.0fs", lagSecs, maxLagSecs)
		}

		st := state[slot]
		if st == nil {
			st = &slotHealth{}
			state[slot] = st
		}

		if reason != "" {
			st.badPolls++
			if st.badPolls >= replAlertAfter && !st.alerting {
				st.alerting = m.sendAlert(ctx, client, fmt.Sprintf(
					"🔴 fc replication STALLED — region=%s slot=%s: %s. Check the peer's apply worker / cross-region path.",
					m.region, slot, reason))
			}
			continue
		}

		// Healthy this poll.
		if st.alerting {
			if m.sendAlert(ctx, client, fmt.Sprintf(
				"🟢 fc replication RECOVERED — region=%s slot=%s: active, replay lag %.0fs.",
				m.region, slot, lagSecs)) {
				st.alerting = false
			}
		}
		st.badPolls = 0
	}
	if err := rows.Err(); err != nil {
		log.WithContext(ctx).Warnf("[repl-monitor] iterate slot rows: %v", err)
		return
	}

	// Drop state for slots that vanished (e.g. a slot dropped by an operator)
	// so the map can't grow unbounded and a re-created slot starts fresh.
	for slot := range state {
		if _, ok := seen[slot]; !ok {
			delete(state, slot)
		}
	}
}

// checkNetworkOwnership detects the security invariant that every sandbox
// attached to an active private network must have the same owner as that
// network. It reports aggregate counts plus at most ten network/sandbox ID
// pairs so an operator can investigate immediately. Tenant identifiers are
// never included. A mismatch alerts immediately and remains quiet until
// recovery, so a persistent bad row cannot spam every minute.
func (m *Monitor) checkNetworkOwnership(ctx context.Context, client *http.Client, alerting *bool) {
	qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var memberships, networks int
	var examples string
	err := m.repo.DB.Con.QueryRow(qctx, `
		WITH mismatches AS MATERIALIZED (
			SELECT n.id AS network_id, s.id AS sandbox_id
			  FROM sandbox_networks sn
			  JOIN networks n ON n.id = sn.network_id
			  JOIN sandboxes s ON s.id = sn.sandbox_id
			 WHERE n.deleted_at IS NULL
			   AND s.region = $1
			   AND s.status NOT IN ('destroyed', 'failed')
			   AND n.owner IS DISTINCT FROM s.created_by
		)
		SELECT COUNT(*)::int,
		       COUNT(DISTINCT network_id)::int,
		       COALESCE((
				SELECT STRING_AGG(network_id || '/' || sandbox_id, ', ' ORDER BY network_id, sandbox_id)
				  FROM (
					SELECT network_id, sandbox_id
					  FROM mismatches
					 ORDER BY network_id, sandbox_id
					 LIMIT 10
				  ) samples
		       ), '')
		  FROM mismatches`, m.region).Scan(&memberships, &networks, &examples)
	if err != nil {
		log.WithContext(ctx).Warnf("[network-ownership-monitor] query ownership state: %v", err)
		return
	}

	if memberships > 0 {
		if !*alerting {
			additional := memberships - 10
			if additional < 0 {
				additional = 0
			}
			*alerting = m.sendAlert(ctx, client, fmt.Sprintf(
				"🔴 fc NETWORK OWNERSHIP VIOLATION — region=%s mismatched_memberships=%d affected_networks=%d examples=[%s] additional=%d. Different tenants may share a private network; inspect sandbox_networks immediately.",
				m.region, memberships, networks, examples, additional))
		}
		return
	}

	if *alerting {
		if m.sendAlert(ctx, client, fmt.Sprintf(
			"🟢 fc network ownership RECOVERED — region=%s: no cross-owner sandbox memberships remain.",
			m.region)) {
			*alerting = false
		}
	}
}

// sendAlert POSTs {"message": ...} to the configured infrastructure alert
// URL. Failures are logged,
// never retried inline. false leaves the caller's transition pending so the
// next poll retries the notification.
func (m *Monitor) sendAlert(ctx context.Context, client *http.Client, message string) bool {
	body, err := json.Marshal(struct {
		Message string `json:"message"`
	}{Message: message})
	if err != nil {
		log.WithContext(ctx).Warnf("[infra-monitor] marshal alert: %v", err)
		return false
	}

	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(pctx, http.MethodPost, m.alertURL, bytes.NewReader(body))
	if err != nil {
		log.WithContext(ctx).Warnf("[infra-monitor] build alert request: %v", err)
		return false
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		log.WithContext(ctx).Warnf("[infra-monitor] post alert: %v", err)
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.WithContext(ctx).Warnf("[infra-monitor] alert webhook returned %d", resp.StatusCode)
		return false
	}
	log.WithContext(ctx).Infof("[infra-monitor] alert sent: %s", message)
	return true
}
