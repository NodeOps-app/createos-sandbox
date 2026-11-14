package vm

import (
	"fmt"

	"github.com/NodeOps-app/createos-sandbox/internal/proto"
)

// This file is the actual implementation of the host-side shape catalog
// surface (Catalog + helpers + Shape alias). The cluster-wide canonical
// catalog lives in the `shapes` DB table; control reads it via the
// DB-backed shape cache and pushes the resolved list to every host on
// register + heartbeat. There is no longer a baked-in fallback slice —
// an empty catalog means "DB unavailable and no heartbeat has landed".

// Shape is the wire type for a catalog entry — alias of proto.Shape so
// callers inside internal/hosts/vm can keep writing `vm.Shape`.
type Shape = proto.Shape

// AllowedDiskSizesMib is the fixed menu of per-VM disk sizes users may pick.
// Picked to simplify the pool layout and keep mkfs cost predictable.
var AllowedDiskSizesMib = []int64{
	10 * 1024,
	20 * 1024,
	30 * 1024,
	40 * 1024,
	50 * 1024,
	60 * 1024,
}

// IsAllowedDiskMib reports whether m is in the allowed disk menu.
func IsAllowedDiskMib(m int64) bool {
	for _, v := range AllowedDiskSizesMib {
		if m == v {
			return true
		}
	}
	return false
}

// Catalog is a registry of known shapes, keyed by ID.
type Catalog struct {
	byID map[string]Shape
	list []Shape
}

// NewCatalog constructs a catalog over the given shapes.
func NewCatalog(shapes []Shape) *Catalog {
	c := &Catalog{byID: make(map[string]Shape, len(shapes)), list: shapes}
	for _, s := range shapes {
		c.byID[s.ID] = s
	}
	return c
}

// Get looks up a shape by ID.
func (c *Catalog) Get(id string) (Shape, bool) {
	s, ok := c.byID[id]
	return s, ok
}

// List returns the catalog in declaration order.
func (c *Catalog) List() []Shape { return c.list }

// IDs returns just the shape IDs (useful for error messages).
func (c *Catalog) IDs() []string {
	out := make([]string, 0, len(c.list))
	for _, s := range c.list {
		out = append(out, s.ID)
	}
	return out
}

// Resolve looks up a shape ID, returning vcpu + mem + the shape's default disk
// + the cgroup CPU-quota percent (0 = unlimited; see Shape.CPUQuotaPct).
// Caller may override disk from the create body.
func (c *Catalog) Resolve(id string) (vcpu int, mem int, defaultDisk int64, cpuQuotaPct int, err error) {
	s, ok := c.byID[id]
	if !ok {
		return 0, 0, 0, 0, fmt.Errorf("unknown shape %q (valid: %v)", id, c.IDs())
	}
	return s.VCPU, s.MemMib, s.DefaultDisk, s.CPUQuotaPct, nil
}
