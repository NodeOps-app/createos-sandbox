package leader

import (
	"testing"

	"go.uber.org/goleak"
)

// Leader election starts a renew loop per elector; a lost cancel here
// leaks one goroutine per instance for the process lifetime. That is the
// same shape as the host-agent idle-CPU accumulation seen on long-running
// hosts, so the packages
// that spawn long-lived loops get a leak check at test time.
//
// Copy this file into any package that starts goroutines from a
// constructor; it needs no per-test wiring.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
