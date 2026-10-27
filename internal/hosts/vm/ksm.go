package vm

import (
	"fmt"
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"
)

// EnableKSM turns on Kernel Same-page Merging — the kernel scans for
// identical 4 KiB pages across processes and merges them copy-on-write.
//
// Why we want it: every microVM running the same rootfs (e.g. python:slim)
// has thousands of page-identical libc/glibc/libpython pages. KSM dedups
// them automatically. Realistic savings: 30–50% RAM at scale, free.
//
// Cost: one low-priority kernel thread (`ksmd`) scanning continuously,
// typically <5% of one CPU. Negligible against the gain.
//
// Tunables (`scan_pages`, `sleep_ms`) trade scan thoroughness for CPU
// overhead. Defaults from upstream Linux are sensible; we override only
// if explicitly asked.
//
// Returns nil if KSM was enabled (or already on); error if the sysctl
// path doesn't exist (kernel built without CONFIG_KSM — rare).
func EnableKSM(scanPages, sleepMs int) error {
	const runPath = "/sys/kernel/mm/ksm/run"
	if _, err := os.Stat(runPath); err != nil {
		return fmt.Errorf("ksm not available: %w", err)
	}
	if err := os.WriteFile(runPath, []byte("1"), 0644); err != nil {
		return fmt.Errorf("enable ksm: %w", err)
	}
	if scanPages > 0 {
		_ = os.WriteFile("/sys/kernel/mm/ksm/pages_to_scan",
			[]byte(strconv.Itoa(scanPages)), 0644)
	}
	if sleepMs > 0 {
		_ = os.WriteFile("/sys/kernel/mm/ksm/sleep_millisecs",
			[]byte(strconv.Itoa(sleepMs)), 0644)
	}
	log.Infof("[ksm] enabled (scan_pages=%d sleep_ms=%d) — duplicate pages across VMs will be merged", scanPages, sleepMs)
	return nil
}
