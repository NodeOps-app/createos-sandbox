package vm

import (
	"fmt"
	"os/exec"
	"strings"
)

// chainExists reads the table successfully before treating a chain as absent.
// A failed named-chain probe cannot distinguish absence from lock/permission errors.
func chainExists(table, chain string) (bool, error) {
	out, err := exec.Command("iptables", "-w", "2", "-t", table, "-S").CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("inspect %s/%s: %w: %s", table, chain, err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && (fields[0] == "-N" || fields[0] == "-P") && fields[1] == chain {
			return true, nil
		}
	}
	return false, nil
}

// iptablesBatcher coalesces concurrent RemoveSandboxIPTables calls into a
// single iptables-restore transaction per xt_lock cycle. Under parallel
// destroy (N=10+), each teardown otherwise takes the lock on its own and
// we see a textbook staircase — 10 destroys finish over ~400 ms when each
// is ~50 ms of serialised kernel work.
//
// Design:
//   - One long-running worker goroutine; Enqueue returns only after the
//     batch containing that job has been applied.
//   - The worker drains everything currently queued, runs ONE
//     iptables-restore, then signals every job in the batch. Jobs that
//     arrive during a running batch wait in the queue and are picked up
//     on the next iteration — so a burst of N simultaneous destroys
//     completes in ~2 iptables-restore invocations (the one already in
//     flight + one covering the rest).
//   - No timers / sleeps: natural coalescing. Single destroys take their
//     iptables time + a zero-overhead channel round-trip.
type iptablesBatcher struct {
	jobs chan *iptablesJob
}

type iptablesJob struct {
	id   string
	veth string
	done chan struct{}
	err  error
}

var defaultIptablesBatcher = newIptablesBatcher()

func newIptablesBatcher() *iptablesBatcher {
	b := &iptablesBatcher{jobs: make(chan *iptablesJob, 1024)}
	go b.run()
	return b
}

// EnqueueTeardown schedules the egress+meter teardown for a sandbox and
// blocks until the batch it joined has been applied. An error means callers
// must not recycle the associated veth/slot.
func EnqueueTeardown(id, veth string) error {
	j := &iptablesJob{id: id, veth: veth, done: make(chan struct{})}
	defaultIptablesBatcher.jobs <- j
	<-j.done
	return j.err
}

func (b *iptablesBatcher) run() {
	for {
		first, ok := <-b.jobs
		if !ok {
			return
		}
		// Drain everything else currently queued without blocking. Anything
		// that arrives AFTER this drain falls into the next iteration.
		batch := []*iptablesJob{first}
	drain:
		for {
			select {
			case j := <-b.jobs:
				batch = append(batch, j)
			default:
				break drain
			}
		}

		err := b.applyBatch(batch)
		for _, j := range batch {
			j.err = err
			close(j.done)
		}
	}
}

// applyBatch builds one iptables-restore script covering every job's
// egress + meter chains, and executes it. Existence probes run first so
// any job with no chains (shouldn't happen in practice, but harmless) is
// a no-op line.
func (b *iptablesBatcher) applyBatch(batch []*iptablesJob) error {
	// Probe existence per-job using cheap read-only iptables calls. This
	// dominates nothing — each probe is ~2 ms and they parallelise poorly
	// anyway, but they're small and unavoidable: iptables-restore aborts
	// the entire batch if any referenced chain is missing.
	type entry struct {
		job             *iptablesJob
		hasNatEgress    bool
		hasFilterEgress bool
		hasDNS          bool
		hasMeter        bool
		hasInMeter      bool
	}
	entries := make([]entry, 0, len(batch))
	for _, j := range batch {
		e := entry{job: j}
		var err error
		e.hasNatEgress, err = chainExists("nat", sandboxChain(j.id))
		if err != nil {
			return err
		}
		e.hasFilterEgress, err = chainExists("filter", sandboxChain(j.id))
		if err != nil {
			return err
		}
		e.hasDNS, err = chainExists("filter", sandboxDNSChain(j.id))
		if err != nil {
			return err
		}
		e.hasMeter, err = chainExists("filter", "fcbw-"+shortHash(j.id))
		if err != nil {
			return err
		}
		e.hasInMeter, err = chainExists("filter", "fcbwin-"+shortHash(j.id))
		if err != nil {
			return err
		}
		if e.hasNatEgress || e.hasFilterEgress || e.hasDNS || e.hasMeter || e.hasInMeter {
			entries = append(entries, e)
		}
	}
	if len(entries) == 0 {
		return nil
	}

	var sb strings.Builder
	anyEgress := false
	for _, e := range entries {
		if e.hasNatEgress {
			anyEgress = true
			break
		}
	}
	if anyEgress {
		sb.WriteString("*nat\n")
		for _, e := range entries {
			if !e.hasNatEgress {
				continue
			}
			ch := sandboxChain(e.job.id)
			fmt.Fprintf(&sb, "-D PREROUTING -i %s -j %s\n-F %s\n-X %s\n",
				e.job.veth, ch, ch, ch)
		}
		sb.WriteString("COMMIT\n")
	}
	sb.WriteString("*filter\n")
	for _, e := range entries {
		if e.hasFilterEgress {
			ch := sandboxChain(e.job.id)
			fmt.Fprintf(&sb, "-D FORWARD -i %s -j %s\n-F %s\n-X %s\n",
				e.job.veth, ch, ch, ch)
		}
		if e.hasDNS {
			ch := sandboxDNSChain(e.job.id)
			fmt.Fprintf(&sb, "-D INPUT -i %s -d 169.254.20.10/32 -j %s\n-F %s\n-X %s\n",
				e.job.veth, ch, ch, ch)
		}
		if e.hasMeter {
			ch := "fcbw-" + shortHash(e.job.id)
			fmt.Fprintf(&sb, "-D FORWARD -i %s -j %s\n-F %s\n-X %s\n",
				e.job.veth, ch, ch, ch)
		}
		if e.hasInMeter {
			ch := "fcbwin-" + shortHash(e.job.id)
			fmt.Fprintf(&sb, "-D INPUT  -i %s -p tcp --sport 1026 -j %s\n", e.job.veth, ch)
			fmt.Fprintf(&sb, "-D OUTPUT -o %s -p tcp --dport 1026 -j %s\n", e.job.veth, ch)
			fmt.Fprintf(&sb, "-F %s\n-X %s\n", ch, ch)
		}
	}
	sb.WriteString("COMMIT\n")
	if err := iptRestore(sb.String()); err != nil {
		return fmt.Errorf("batch iptables teardown: %w", err)
	}
	return nil
}
