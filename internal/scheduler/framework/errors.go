package framework

import "errors"

var (
	// ErrNoCapacity is returned by Pipeline.Schedule when no host survives
	// filters or every survivor's reserve attempt failed.
	ErrNoCapacity = errors.New("scheduler: no host with capacity")
	// ErrConflict is returned by a Reserver when it lost a race (in-mem
	// over-commit, LWT contention, etc). The pipeline drops that host and
	// retries the next-best.
	ErrConflict = errors.New("reserver: lost race")
	// ErrUnknownHost is returned by Reserver.Release when the token is not
	// known. Reserver implementations may also choose to ignore this.
	ErrUnknownHost = errors.New("scheduler: unknown host")
	// ErrUnknownPlugin is returned by Registry.BuildPipeline when a name
	// in PipelineSpec is not registered.
	ErrUnknownPlugin = errors.New("scheduler: unknown plugin")
)
