package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// LocalCache wraps an underlying Storage with a host-local directory
// cache. Get checks the local cache first; on a miss it falls through
// to the underlying Storage and the caller is responsible for writing
// the bytes back into Dir if they want a future fast path. Put is a
// pass-through — pause writes the local files itself (in the same
// directory we already used for the snapshot temp files) and the
// LocalCache only matters on resume.
//
// Verification (sha256 against the manifest) is the caller's job.
// LocalCache is just a path-based io shortcut; it doesn't know about
// manifests.
type LocalCache struct {
	Dir        string
	Underlying Storage
}

func (lc *LocalCache) ensureDir(key string) error {
	full := filepath.Join(lc.Dir, key)
	return os.MkdirAll(filepath.Dir(full), 0o755)
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

// GetWithCachePopulate is like Get, but on a local-cache miss it
// streams the underlying Storage into <Dir>/<key> AS WELL AS returning
// the bytes to the caller. Implemented via io.TeeReader so the caller
// gets a single sequential read and the local file is written
// concurrently.
//
// Used by resume so a cross-host resume that paid for an R2 download
// leaves a populated locality cache for any next-touch.
func (lc *LocalCache) GetWithCachePopulate(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	// Local hit: same as Get.
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
		return nil, 0, fmt.Errorf("local cache open %s: %w", key, err)
	}

	// Underlying fetch. Tee through a temp file then rename, so a
	// crashed write doesn't leave a corrupt cache entry.
	if err := lc.ensureDir(key); err != nil {
		return nil, 0, fmt.Errorf("local cache mkdir %s: %w", key, err)
	}
	src, size, err := lc.Underlying.Get(ctx, key)
	if err != nil {
		return nil, 0, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(lc.localPath(key)), filepath.Base(key)+".tmp.*")
	if err != nil {
		src.Close()
		return nil, 0, fmt.Errorf("local cache tmp: %w", err)
	}
	tee := io.TeeReader(src, tmp)
	finalPath := lc.localPath(key)
	return &teedReader{
		tee:  tee,
		src:  src,
		tmp:  tmp,
		dest: finalPath,
	}, size, nil
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

// teedReader is the body returned by GetWithCachePopulate. Reading it
// pulls from the underlying Storage AND writes to a temp file; on
// Close the temp file is renamed to its final path (only if no read
// error has been observed). An error during the read leaves the temp
// file behind for janitorial cleanup but never corrupts the final
// cache entry.
type teedReader struct {
	tee     io.Reader
	src     io.ReadCloser
	tmp     *os.File
	dest    string
	readErr error
}

func (t *teedReader) Read(p []byte) (int, error) {
	n, err := t.tee.Read(p)
	if err != nil && err != io.EOF {
		t.readErr = err
	}
	return n, err
}

func (t *teedReader) Close() error {
	closeErr := t.src.Close()
	if syncErr := t.tmp.Sync(); syncErr != nil && t.readErr == nil {
		t.readErr = syncErr
	}
	tmpPath := t.tmp.Name()
	if err := t.tmp.Close(); err != nil && t.readErr == nil {
		t.readErr = err
	}
	if t.readErr != nil {
		// Don't promote a partial cache entry; remove the tmp.
		_ = os.Remove(tmpPath)
		return t.readErr
	}
	if err := os.Rename(tmpPath, t.dest); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("local cache rename: %w", err)
	}
	return closeErr
}
