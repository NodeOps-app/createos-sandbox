package sandboxaccess

import (
	"context"

	"github.com/NodeOps-app/sandbox/internal/apiserver/userapikey"
	"github.com/NodeOps-app/sandbox/models"
)

type ResolvedToken struct {
	SandboxID string
	TokenHint string
}

type tokenStore interface {
	LookupSandboxAccessTokenByHash(ctx context.Context, tokenHash []byte) (*models.SandboxAccessToken, error)
}

// Resolver authenticates sandbox tokens against durable storage on every
// request. There is intentionally no positive cache yet: rotate, disable, and
// destroy must take effect immediately across all control replicas.
type Resolver struct {
	store  tokenStore
	hasher *userapikey.Hasher
}

func NewResolver(store tokenStore, hasher *userapikey.Hasher) *Resolver {
	return &Resolver{store: store, hasher: hasher}
}

func (r *Resolver) Resolve(ctx context.Context, token string) (ResolvedToken, bool, error) {
	if r == nil || r.store == nil {
		return ResolvedToken{}, false, nil
	}
	digest, err := Hash(r.hasher, token)
	if err != nil {
		return ResolvedToken{}, false, nil
	}
	record, err := r.store.LookupSandboxAccessTokenByHash(ctx, digest)
	if err != nil {
		return ResolvedToken{}, false, err
	}
	if record == nil {
		return ResolvedToken{}, false, nil
	}
	return ResolvedToken{
		SandboxID: record.SandboxID,
		TokenHint: record.TokenHint,
	}, true, nil
}
