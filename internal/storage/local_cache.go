package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// LocalCache checks a host-local directory before the underlying Storage.
// Get and GetRange do not populate misses; Put and Copy pass through.
// Callers provide trusted relative keys and manage integrity verification,
// cache population, and retention outside this wrapper.
type LocalCache struct {
	Dir        string
	Underlying Storage
}

func (lc *LocalCache) localPath(key string) string {
	return filepath.Join(lc.Dir, key)
}

func (lc *LocalCache) Put(ctx context.Context, key string, body io.Reader, size int64, sha256Hex string) error {
	return lc.Underlying.Put(ctx, key, body, size, sha256Hex)
}

// Get tries the local file first; on miss falls through to underlying.
// The local file is opened with O_RDONLY so concurrent reads are safe.
func (lc *LocalCache) Get(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	f, err := os.Open(lc.localPath(key))
	if err == nil {
		stat, statErr := f.Stat()
		if statErr != nil {
			f.Close()
			return nil, 0, fmt.Errorf("local cache stat %s: %w", key, statErr)
		}
		return f, stat.Size(), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		// Local IO error other than ENOENT — surface it; falling
		// through to the underlying could mask real disk problems.
		return nil, 0, fmt.Errorf("local cache open %s: %w", key, err)
	}
	return lc.Underlying.Get(ctx, key)
}

func (lc *LocalCache) GetRange(ctx context.Context, key string, offset int64) (io.ReadCloser, int64, error) {
	f, err := os.Open(lc.localPath(key))
	if err == nil {
		stat, statErr := f.Stat()
		if statErr != nil {
			f.Close()
			return nil, 0, fmt.Errorf("local cache stat %s: %w", key, statErr)
		}
		if offset < 0 || offset > stat.Size() {
			f.Close()
			return nil, 0, fmt.Errorf("local cache range %s: invalid offset %d", key, offset)
		}
		if _, seekErr := f.Seek(offset, io.SeekStart); seekErr != nil {
			f.Close()
			return nil, 0, fmt.Errorf("local cache seek %s: %w", key, seekErr)
		}
		return f, stat.Size(), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, 0, fmt.Errorf("local cache open %s: %w", key, err)
	}
	return lc.Underlying.GetRange(ctx, key, offset)
}

func (lc *LocalCache) Copy(ctx context.Context, srcKey, dstKey string) error {
	return lc.Underlying.Copy(ctx, srcKey, dstKey)
}

func (lc *LocalCache) Delete(ctx context.Context, key string) error {
	// Best-effort local delete; ignore not-found.
	_ = os.Remove(lc.localPath(key))
	return lc.Underlying.Delete(ctx, key)
}

// DeleteLocalOnly removes the local copy without touching the
// underlying Storage. Used by the host's reaper when TTL expires.
func (lc *LocalCache) DeleteLocalOnly(key string) error {
	err := os.Remove(lc.localPath(key))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (lc *LocalCache) Exists(ctx context.Context, key string) (bool, error) {
	if _, err := os.Stat(lc.localPath(key)); err == nil {
		return true, nil
	}
	return lc.Underlying.Exists(ctx, key)
}
