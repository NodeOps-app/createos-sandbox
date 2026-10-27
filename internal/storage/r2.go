package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
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
	opts := minio.PutObjectOptions{
		// Multipart auto-engages when size==-1 OR size > 16MiB. We let
		// the SDK pick the part count — for our typical 1 GB memfile
		// this lands at ~10 parts of 100 MiB each.
		PartSize: 100 * 1024 * 1024,
	}
	// minio-go computes Content-MD5 itself for non-multipart uploads;
	// for multipart it uses per-part MD5s. The application-level
	// sha256 we keep in the manifest is verified independently by
	// the caller (TeeReader) — we don't push it to the server here
	// because not every S3-compat backend supports x-amz-checksum-sha256
	// (R2 does; MinIO old versions don't).
	_, err := r.cli.PutObject(ctx, r.bucket, key, body, size, opts)
	if err != nil {
		return fmt.Errorf("r2 put %s: %w", key, err)
	}
	return nil
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
	// Server-side CopyObject is faster (zero egress) but minio-go v7.1.0
	// against MinIO 2024-12+ intermittently returns SignatureDoesNotMatch
	// — known signing-canonical-form mismatch on the x-amz-copy-source
	// header. Try server-side first; on any signature/auth error fall
	// back to stream Get → Put.
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
// under the 10 000-part composeObject ceiling for up-to-2.5 TiB
// sources. For a 6 GiB overlay this is 24 parts.
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
