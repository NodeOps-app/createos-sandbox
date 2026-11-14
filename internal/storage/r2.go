package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	log "github.com/sirupsen/logrus"
)

// R2Config are the inputs to NewR2. Same shape works for AWS S3,
// Cloudflare R2, MinIO, Hetzner Object Storage — anything that
// speaks SigV4 over HTTPS.
type R2Config struct {
	Endpoint        string // e.g. "https://<account>.r2.cloudflarestorage.com"
	Region          string // e.g. "auto" for R2, "us-east-1" for AWS, etc.
	AccessKeyID     string
	SecretAccessKey string
	Bucket          string
	Secure          bool // true for HTTPS
}

// R2 is a thin wrapper around minio-go. The minio-go client itself is
// safe for concurrent use; this struct is just config + a shared
// client handle.
type R2 struct {
	cli    *minio.Client
	bucket string
}

func NewR2(cfg R2Config) (*R2, error) {
	if cfg.Endpoint == "" || cfg.Bucket == "" || cfg.AccessKeyID == "" || cfg.SecretAccessKey == "" {
		return nil, fmt.Errorf("r2: endpoint, bucket, access key id, and secret all required")
	}
	cli, err := minio.New(stripScheme(cfg.Endpoint), &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		Secure: cfg.Secure,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("r2: %w", err)
	}
	return &R2{cli: cli, bucket: cfg.Bucket}, nil
}

func (r *R2) Put(ctx context.Context, key string, body io.Reader, size int64, sha256Hex string) error {
	start := time.Now()
	entry := log.WithContext(ctx).WithFields(log.Fields{"object": key, "bytes": size})
	ctx, cancel := context.WithCancelCause(ctx)
	progress := &uploadProgress{start: start}
	done := make(chan struct{})
	go func(ctx context.Context) {
		defer close(done)
		progress.watch(ctx, cancel, entry, 3*time.Minute, 30*time.Second)
	}(ctx)
	defer func() { cancel(nil); <-done }()
	// Trace timings only: HTTP headers and URLs may contain storage credentials.
	// Each SDK retry emits another request_sent event; multipart parts do too.
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			entry.WithFields(log.Fields{"elapsed": time.Since(start), "write_failed": info.Err != nil}).Info("[storage-upload] request_sent")
		},
		GotFirstResponseByte: func() {
			entry.WithField("elapsed", time.Since(start)).Info("[storage-upload] response_started")
		},
	})
	opts := minio.PutObjectOptions{
		// Preserve the SDK's seekable file/multipart path. Wrapping body itself
		// in a counting reader would hide ReaderAt and change that path.
		PartSize: 100 * 1024 * 1024,
		Progress: progress,
	}
	// sha256Hex is not sent as a server-side checksum assertion. Callers
	// maintain and verify the manifest checksum independently; the SDK handles
	// its own transfer protocol checks.
	_, err := r.cli.PutObject(ctx, r.bucket, key, body, size, opts)
	if err != nil {
		fields := log.Fields{"elapsed": time.Since(start), "source_bytes_read": progress.bytes.Load(), "idle_timeout": errors.Is(context.Cause(ctx), errUploadIdle)}
		var response minio.ErrorResponse
		if errors.As(err, &response) {
			// Never log raw messages, headers, or signed URLs from the backend.
			fields["http_status"] = response.StatusCode
		}
		entry.WithFields(fields).Warn("[storage-upload] failed")
		if errors.Is(context.Cause(ctx), errUploadIdle) {
			err = errUploadIdle
		}
		return fmt.Errorf("r2 put %s: %w", key, err)
	}
	entry.WithField("elapsed", time.Since(start)).Info("[storage-upload] completed")
	return nil
}

var errUploadIdle = errors.New("storage upload made no progress before idle timeout")

// The SDK calls Read as it consumes each request body. This measures client
// activity, not remote durability; retries can count the same bytes again.
// Atomic counters are required because multipart workers run concurrently.
type uploadProgress struct {
	start time.Time
	bytes atomic.Int64
	last  atomic.Int64
}

func (p *uploadProgress) Read(b []byte) (int, error) {
	if len(b) > 0 {
		p.bytes.Add(int64(len(b)))
		p.last.Store(time.Since(p.start).Nanoseconds())
	}
	return len(b), nil
}

func (p *uploadProgress) watch(ctx context.Context, cancel context.CancelCauseFunc, entry *log.Entry, idle, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			elapsed := time.Since(p.start)
			idleFor := elapsed - time.Duration(p.last.Load())
			entry.WithFields(log.Fields{"elapsed": elapsed, "source_bytes_read": p.bytes.Load(), "idle_for": idleFor}).Info("[storage-upload] progress")
			// Also bounds waiting for a response after the final body bytes.
			// The caller's total deadline still applies even if reads continue.
			if idleFor >= idle {
				cancel(errUploadIdle)
				return
			}
		}
	}
}

func (r *R2) Get(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	obj, err := r.cli.GetObject(ctx, r.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, 0, fmt.Errorf("r2 get %s: %w", key, err)
	}
	// minio-go's GetObject is lazy — it doesn't HTTP until first read.
	// Stat to surface a 404 immediately so callers can errors.Is(ErrNotFound).
	stat, err := obj.Stat()
	if err != nil {
		obj.Close()
		if isNotFound(err) {
			return nil, 0, ErrNotFound
		}
		return nil, 0, fmt.Errorf("r2 stat %s: %w", key, err)
	}
	return obj, stat.Size, nil
}

func (r *R2) GetRange(ctx context.Context, key string, offset int64) (io.ReadCloser, int64, error) {
	if offset < 0 {
		return nil, 0, fmt.Errorf("r2 get range %s: negative offset %d", key, offset)
	}
	opts := minio.GetObjectOptions{}
	if offset > 0 {
		if err := opts.SetRange(offset, 0); err != nil {
			return nil, 0, fmt.Errorf("r2 get range %s: %w", key, err)
		}
	}
	obj, err := r.cli.GetObject(ctx, r.bucket, key, opts)
	if err != nil {
		return nil, 0, fmt.Errorf("r2 get range %s: %w", key, err)
	}
	stat, err := r.cli.StatObject(ctx, r.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		obj.Close()
		if isNotFound(err) {
			return nil, 0, ErrNotFound
		}
		return nil, 0, fmt.Errorf("r2 stat %s: %w", key, err)
	}
	return obj, stat.Size, nil
}

func (r *R2) Copy(ctx context.Context, srcKey, dstKey string) error {
	// R2/S3 single-request CopyObject is capped at 5 GiB. Any fork of a
	// sandbox whose compressed overlay (or any other artifact) exceeds
	// that limit gets a hard "Your proposed upload exceeds the maximum
	// allowed object size" and hangs the fork. Above 5 GiB we split the
	// source into byte ranges and issue ComposeObject, which under the
	// hood uses UploadPartCopy — still fully server-side (no egress).
	stat, statErr := r.cli.StatObject(ctx, r.bucket, srcKey, minio.StatObjectOptions{})
	if statErr == nil && stat.Size > maxSingleCopyBytes {
		return r.copyMultipart(ctx, srcKey, dstKey, stat.Size)
	}
	// Prefer server-side copy. The signature-error fallback below streams
	// through this client; other errors are returned without that fallback.
	_, err := r.cli.CopyObject(ctx,
		minio.CopyDestOptions{Bucket: r.bucket, Object: dstKey},
		minio.CopySrcOptions{Bucket: r.bucket, Object: srcKey},
	)
	if err == nil {
		return nil
	}
	es := err.Error()
	if !strings.Contains(es, "SignatureDoesNotMatch") &&
		!strings.Contains(es, "request signature we calculated does not match") {
		return fmt.Errorf("r2 copy %s -> %s: %w", srcKey, dstKey, err)
	}
	// Fallback: stream the object through the client.
	obj, err := r.cli.GetObject(ctx, r.bucket, srcKey, minio.GetObjectOptions{})
	if err != nil {
		return fmt.Errorf("r2 copy fallback get %s: %w", srcKey, err)
	}
	defer obj.Close()
	fbStat, err := obj.Stat()
	if err != nil {
		return fmt.Errorf("r2 copy fallback stat %s: %w", srcKey, err)
	}
	if _, err := r.cli.PutObject(ctx, r.bucket, dstKey, obj, fbStat.Size,
		minio.PutObjectOptions{ContentType: fbStat.ContentType}); err != nil {
		return fmt.Errorf("r2 copy fallback put %s: %w", dstKey, err)
	}
	return nil
}

// maxSingleCopyBytes is the R2/S3 hard limit on a single CopyObject.
// Beyond this we must use multipart (ComposeObject → UploadPartCopy).
const maxSingleCopyBytes int64 = 5 * 1024 * 1024 * 1024

// copyMultipart clones a large object entirely server-side by slicing
// the source into byte ranges and issuing ComposeObject. minio-go
// translates each source range into an UploadPartCopy call and
// stitches the parts with CompleteMultipartUpload. No bytes egress
// through this process.
//
// Part size is 256 MiB — well above R2's 5 MiB min-part floor and
// small enough to keep the per-part API call quick while staying
// under 10,000 parts for sources below roughly 2.44 TiB.
// For a 6 GiB overlay this is 24 parts.
func (r *R2) copyMultipart(ctx context.Context, srcKey, dstKey string, size int64) error {
	const partSize int64 = 256 * 1024 * 1024
	var srcs []minio.CopySrcOptions
	for off := int64(0); off < size; off += partSize {
		end := off + partSize - 1
		if end >= size {
			end = size - 1
		}
		srcs = append(srcs, minio.CopySrcOptions{
			Bucket:     r.bucket,
			Object:     srcKey,
			MatchRange: true,
			Start:      off,
			End:        end,
		})
	}
	if _, err := r.cli.ComposeObject(ctx,
		minio.CopyDestOptions{Bucket: r.bucket, Object: dstKey},
		srcs...,
	); err != nil {
		return fmt.Errorf("r2 multipart copy %s -> %s (size=%d, parts=%d): %w",
			srcKey, dstKey, size, len(srcs), err)
	}
	return nil
}

func (r *R2) Delete(ctx context.Context, key string) error {
	err := r.cli.RemoveObject(ctx, r.bucket, key, minio.RemoveObjectOptions{})
	if err != nil && !isNotFound(err) {
		return fmt.Errorf("r2 delete %s: %w", key, err)
	}
	return nil
}

func (r *R2) Exists(ctx context.Context, key string) (bool, error) {
	_, err := r.cli.StatObject(ctx, r.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("r2 stat %s: %w", key, err)
	}
	return true, nil
}

func isNotFound(err error) bool {
	var resp minio.ErrorResponse
	if errors.As(err, &resp) {
		return resp.StatusCode == http.StatusNotFound || resp.Code == "NoSuchKey" || resp.Code == "NotFound"
	}
	return false
}

// stripScheme drops a leading https:// or http:// from an endpoint
// because minio-go's New takes the host[:port] without a scheme and
// the Secure flag selects HTTP/HTTPS.
func stripScheme(s string) string {
	for _, prefix := range []string{"https://", "http://"} {
		if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
			return s[len(prefix):]
		}
	}
	return s
}
