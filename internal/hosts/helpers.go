package hosts

import (
	"github.com/NodeOps-app/sandbox/internal/hosts/vm"
)

// mgrStater adapts *vm.Manager to HeartbeatStater. Kept here so vm and
// the heartbeat loop don't import each other.
type mgrStater struct{ m *vm.Manager }

func (a *mgrStater) Snapshot() (int, int) {
	a.m.Mu.RLock()
	defer a.m.Mu.RUnlock()
	var mem, count int
	for _, sb := range a.m.Sandboxes {
		mem += sb.MemMib
		count++
	}
	return mem, count
}

// Compile-time check that mgrStater satisfies HeartbeatStater.
var _ HeartbeatStater = (*mgrStater)(nil)
