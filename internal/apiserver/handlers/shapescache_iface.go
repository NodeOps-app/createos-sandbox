package handlers

import (
	"context"

	"github.com/NodeOps-app/createos-sandbox/internal/proto"
)

// ShapesProvider is the narrow interface the handlers use to read the
// current VM shape catalog. Implemented by *cache.Shapes (which
// hits Postgres with a TTL cache). Declared here so the handlers
// package does not import internal/apiserver (which would create an
// import cycle).
type ShapesProvider interface {
	Shapes(ctx context.Context) []proto.Shape
}
