package vm

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
)

// iptablesInstallBatcher coalesces concurrent egress-install calls into
// a single iptables-restore transaction. Mirror of the teardown batcher
// (iptables_batcher.go); same channel-drain pattern, same xt_lock
// rationale.
//
// Why: under 100-wide spawn burst, each VM's InstallEgress hits the
// kernel's global xt_lock independently — measured net-phase variance
// of 3–416 ms with median ~100 ms after cpu-lane isolation removed the
// pure-CPU bottleneck. Batching collapses N concurrent installs into
// ~2 iptables-restore transactions (the one in flight + one covering
// the rest of the burst).
//
// Design:
//   - One long-running worker goroutine; EnqueueInstall returns only
//     after the batch containing the job has been applied.
//   - The worker drains everything currently queued, runs ONE
//     iptables-restore that opens *nat and *filter once and stuffs
//     every job's rules in, then signals every job.
//   - Jobs whose rules are empty or "*" are no-ops at the iptables
//     layer (allow-all). They short-circuit before enqueue.
//   - On iptables-restore failure the whole batch fails — kernel
//     applies the transaction atomically, so partial success isn't a
//     thing. Callers retry as a single VM, hitting the slow path.
type iptablesInstallBatcher struct {
	jobs chan *installJob
}

type installJob struct {
	id    string
	vmIP  string
	veth  string
	rules []string
	done  chan error
}

var defaultIptablesInstallBatcher = newInstallBatcher()

func newInstallBatcher() *iptablesInstallBatcher {
	b := &iptablesInstallBatcher{jobs: make(chan *installJob, 1024)}
	go b.run()
	return b
}

// EnqueueInstall schedules an egress-rule install for a sandbox and
// blocks until the batch it joined has been applied. Returns whatever
// iptables-restore returned for the combined batch.
func EnqueueInstall(id, vmIP, veth string, rules []string) error {
	// Allow-all / empty rules: nothing for iptables to do. Inline.
	if len(rules) == 0 {
		return nil
	}
	j := &installJob{
		id:    id,
		vmIP:  vmIP,
		veth:  veth,
		rules: rules,
		done:  make(chan error, 1),
	}
	defaultIptablesInstallBatcher.jobs <- j
	return <-j.done
}

func (b *iptablesInstallBatcher) run() {
	for {
		first, ok := <-b.jobs
		if !ok {
			return
		}
		// Drain everything else currently queued non-blocking. Anything
		// that arrives AFTER this drain falls into the next iteration.
		batch := []*installJob{first}
	drain:
		for {
			select {
			case j := <-b.jobs:
				batch = append(batch, j)
			default:
				break drain
			}
		}
		b.applyBatch(batch)
	}
}

// applyBatch builds ONE iptables-restore script containing every job's
// nat + filter rules and runs it. Each job is signaled with the
// combined batch's error (nil on success).
func (b *iptablesInstallBatcher) applyBatch(batch []*installJob) {
	type entry struct {
		job         *installJob
		natChunk    string
		filterChunk string
	}
	work := make([]entry, 0, len(batch))
	for _, j := range batch {
		nat, filter, ok := buildEgressRuleChunks(j.id, j.vmIP, j.veth, j.rules)
		if !ok {
			j.done <- fmt.Errorf("invalid egress rules")
			continue
		}
		if nat == "" && filter == "" {
			// allow-all path produced no chunks; signal success.
			j.done <- nil
			continue
		}
		work = append(work, entry{job: j, natChunk: nat, filterChunk: filter})
	}
	if len(work) == 0 {
		return
	}

	// Stale-chain cleanup: for fresh spawns this is a no-op (chain
	// doesn't exist yet) but pause/resume reuses ids, so be safe. The
	// cleanup uses its own single-txn restore; one extra xt_lock cycle
	// per *batch* (not per job) — amortizes cleanly.
	for _, e := range work {
		RemoveSandboxIPTables(e.job.id, e.job.veth)
	}

	var nat, filter strings.Builder
	nat.WriteString("*nat\n")
	filter.WriteString("*filter\n")
	for _, e := range work {
		nat.WriteString(e.natChunk)
		filter.WriteString(e.filterChunk)
	}
	nat.WriteString("COMMIT\n")
	filter.WriteString("COMMIT\n")

	err := iptRestore(nat.String() + filter.String())
	if err != nil {
		log.Warnf("[egress] batched install of %d sandbox(es) failed: %v", len(work), err)
	} else if len(work) > 1 {
		log.Infof("[egress] batched install ok for %d sandboxes", len(work))
	}
	for _, e := range work {
		e.job.done <- err
	}
}
