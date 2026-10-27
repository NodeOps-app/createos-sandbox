package builder

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"time"

	"github.com/minio/minio-go/v7"

	"github.com/NodeOps-app/sandbox/internal/jwt"
)

// GrantTTL is how long the per-build grants (JWT + presigned URLs)
// remain valid. Must comfortably exceed the build timeout (10 min)
// because the build sandbox uses these grants near the end of the build.
const GrantTTL = 30 * time.Minute

// Grants is the bundle of credentials issued to one build sandbox.
// Scoped to a single tpl_id; all expire within GrantTTL.
//
// Build logs are streamed to control's POST /v1/internal/templates/:id/log
// (ClickHouse-backed) using the same JWT — no R2 grant needed for logs.
type Grants struct {
	JWT          string // sub=tpl_<id>, aud=control
	RootfsPutURL string // R2 PUT signed URL for templates/<id>/rootfs.ext4.zst
}

// GrantIssuer mints per-build grants. Holds the builder's signing key
// and an R2 client for pre-signing.
type GrantIssuer struct {
	signer *jwt.Signer
	bucket string
	r2     *minio.Client
}

// NewGrantIssuer wires the JWT signer and minio client.
func NewGrantIssuer(signer *jwt.Signer, r2 *minio.Client, bucket string) *GrantIssuer {
	return &GrantIssuer{signer: signer, r2: r2, bucket: bucket}
}

// Issue mints a fresh JWT + two presigned PUT URLs for tplID.
func (g *GrantIssuer) Issue(ctx context.Context, tplID string) (*Grants, error) {
	now := time.Now().UTC()
	claims := jwt.Claims{
		Iss: g.signer.KID(),
		Sub: tplID,
		Aud: jwt.AudControl,
		Iat: now.Unix(),
		Nbf: now.Add(-jwt.SkewLeeway).Unix(),
		Exp: now.Add(GrantTTL).Unix(),
		Jti: shortJTI(tplID, now),
	}
	tok, err := g.signer.SignClaims(claims)
	if err != nil {
		return nil, fmt.Errorf("sign jwt: %w", err)
	}

	rootfsKey := "templates/" + tplID + "/rootfs.ext4.zst"
	rootfsURL, err := g.presignPut(ctx, rootfsKey)
	if err != nil {
		return nil, fmt.Errorf("presign rootfs: %w", err)
	}
	return &Grants{
		JWT:          tok,
		RootfsPutURL: rootfsURL.String(),
	}, nil
}

func (g *GrantIssuer) presignPut(ctx context.Context, key string) (*url.URL, error) {
	return g.r2.PresignedPutObject(ctx, g.bucket, key, GrantTTL)
}

// shortJTI is a deterministic-ish jti for log correlation. Not security-
// sensitive — the (kid, sub, exp) tuple already pins the token.
func shortJTI(tplID string, t time.Time) string {
	h := sha256.Sum256([]byte(tplID + t.Format(time.RFC3339Nano)))
	return hex.EncodeToString(h[:8])
}
