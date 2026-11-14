// Package storage is createos's blob storage abstraction.
//
// Two impls today:
//   - r2.go      MinIO/R2/S3 client backed by github.com/minio/minio-go/v7
//   - mem.go     in-memory fake for tests
//
// LocalCache adds optional host-local reads to the remote storage backend.
// Callers manage cache population, integrity checks, and retention. The same
// storage interface serves pause bundles, reusable snapshots, and templates.
package storage

import (
	"context"
	"errors"
	"io"
)

// ErrNotFound is returned by object reads on a missing key. Callers
// should errors.Is(err, ErrNotFound) rather than string-matching.
var ErrNotFound = errors.New("storage: object not found")

// Storage is the minimum API needed for paused-bundle and template
// distribution. Remote operations receive the caller's context; local-cache
// and in-memory operations do not necessarily observe cancellation.
type Storage interface {
	// Put streams body into the named object, replacing any existing object.
	// size is the object size, or -1 for SDK-managed multipart sizing. The
	// current backends do not enforce sha256Hex; callers verify integrity
	// against the manifest independently.
	Put(ctx context.Context, key string, body io.Reader, size int64, sha256Hex string) error

	// Get streams the object. Caller must Close the returned reader.
	// Returns (nil, 0, ErrNotFound) on a missing key.
	Get(ctx context.Context, key string) (io.ReadCloser, int64, error)

	// GetRange streams an object starting at offset and returns the total
	// object size (not merely the response body length). It is used to resume
	// interrupted artifact downloads without restarting from byte zero.
	GetRange(ctx context.Context, key string, offset int64) (io.ReadCloser, int64, error)

	// Copy clones an object, using server-side copy where supported. The S3
	// backend streams through this process for its signature-error fallback.
	// Used by fork to clone a paused bundle into a new key prefix.
	// Overwrites dst if it already exists.
	Copy(ctx context.Context, srcKey, dstKey string) error

	// Delete is idempotent: missing keys are not an error.
	Delete(ctx context.Context, key string) error

	// Exists checks object presence, using HEAD on the remote backend or
	// local metadata for cache and memory implementations.
	Exists(ctx context.Context, key string) (bool, error)
}
