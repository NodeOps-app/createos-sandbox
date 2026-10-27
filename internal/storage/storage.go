// Package storage is createos's blob storage abstraction.
//
// Two impls today:
//   - r2.go      MinIO/R2/S3 client backed by github.com/minio/minio-go/v7
//   - mem.go     in-memory fake for tests
//
// LocalCache wraps any Storage with a host-local cache directory: Get
// checks <Dir>/<key> first and falls through to the underlying Storage
// on miss. Used by the resume path so a host that already has the
// paused bundle on disk doesn't re-download it from R2.
//
// The shape was chosen for two callers — pause/resume and the future
// user-defined-templates feature — so the interface stays
// provider-agnostic and free of pause-specific concepts.
package storage

import (
	"context"
	"errors"
	"io"
)

// ErrNotFound is returned by Get / Head on a missing key. Callers
// should errors.Is(err, ErrNotFound) rather than string-matching.
var ErrNotFound = errors.New("storage: object not found")

// Storage is the minimum API needed for paused-bundle and template
// distribution. All methods are context-aware; cancellation aborts
// the in-flight HTTP call.
type Storage interface {
	// Put streams body into the named object. size is required (R2
	// needs Content-Length); pass -1 to use multipart auto-sizing.
	// sha256Hex (lowercase hex) is asserted via x-amz-checksum-sha256;
	// pass "" to skip the assertion. Overwrites any existing object.
	Put(ctx context.Context, key string, body io.Reader, size int64, sha256Hex string) error

	// Get streams the object. Caller must Close the returned reader.
	// Returns (nil, 0, ErrNotFound) on a missing key.
	Get(ctx context.Context, key string) (io.ReadCloser, int64, error)

	// GetRange streams an object starting at offset and returns the total
	// object size (not merely the response body length). It is used to resume
	// interrupted artifact downloads without restarting from byte zero.
	GetRange(ctx context.Context, key string, offset int64) (io.ReadCloser, int64, error)

	// Copy is a server-side copy: bytes never transit our process.
	// Used by fork to clone a paused bundle into a new key prefix.
	// Overwrites dst if it already exists.
	Copy(ctx context.Context, srcKey, dstKey string) error

	// Delete is idempotent: missing keys are not an error.
	Delete(ctx context.Context, key string) error

	// Exists is a HEAD; cheaper than Get when you only need to know
	// the object is there.
	Exists(ctx context.Context, key string) (bool, error)
}
