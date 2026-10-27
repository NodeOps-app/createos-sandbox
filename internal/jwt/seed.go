// Package jwt implements minimal EdDSA-only JSON Web Tokens for createos's
// internal RPC auth. Stdlib only (crypto/ed25519, encoding/json, encoding/base64).
//
// We don't pull a generic JWT library because createos only needs:
//   - one alg ("EdDSA")
//   - one claim shape (Claims below)
//   - kid-based key lookup at verify time
//
// The full RFC 7519 surface (alg negotiation, RSA, HMAC, JWE, etc.) is dead
// weight. The trimmed implementation is ~150 LOC across this package.
package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"syscall"

	log "github.com/sirupsen/logrus"
)

// LoadOrGenerateSeed reads a 32-byte ed25519 seed from path, generating a
// fresh keypair and persisting the seed at path if the file doesn't exist.
// Same wire format as the gateway's host-key file (internal/gateway/gateway.go),
// so operators can mix-and-match if they ever want to.
//
// File mode is 0600 (root-only). Caller is responsible for ensuring the
// parent directory exists with appropriate permissions.
func LoadOrGenerateSeed(path string) (ed25519.PrivateKey, error) {
	seed, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		_, priv, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			return nil, fmt.Errorf("generate key: %w", gerr)
		}
		seed = priv.Seed()
		if werr := os.WriteFile(path, seed, 0o600); werr != nil {
			return nil, fmt.Errorf("persist seed: %w", werr)
		}
		return priv, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read seed: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("seed file %q must contain a %d-byte ed25519 seed (got %d)",
			path, ed25519.SeedSize, len(seed))
	}
	// Defense against drift: if an operator (or a copy/restore) widened the
	// perms, log loudly and re-tighten to 0600. The private key only needs
	// to be root-readable; anything wider is a misconfiguration.
	enforceKeyFilePerms(path)
	return ed25519.NewKeyFromSeed(seed), nil
}

// enforceKeyFilePerms verifies the file is mode 0600 and corrects it if not.
// Best-effort: in k8s the key is mounted from a Secret on a read-only volume
// at a mode the operator chose (typically 0400 or 0444) — chmod fails with
// EROFS, which is expected, not a problem. Only warn when the file IS on a
// writable filesystem and is wider than 0600.
func enforceKeyFilePerms(path string) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	mode := info.Mode().Perm()
	if mode == 0o600 {
		return
	}
	if err := os.Chmod(path, 0o600); err == nil {
		return
	} else if errors.Is(err, syscall.EROFS) {
		// Read-only mount — the operator picked the mode via k8s Secret
		// defaultMode (or equivalent). Stay quiet; it's not fixable here.
		return
	} else {
		log.Warnf("[jwt] signing key %q had insecure permissions %o and chmod 0600 failed: %v", path, mode, err)
	}
}

// LoadPublicKey reads a raw 32-byte ed25519 public key from path. Used by
// host config to load control/ingress/gateway pubkeys on startup.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read pubkey %q: %w", path, err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("pubkey file %q must contain a %d-byte ed25519 public key (got %d)",
			path, ed25519.PublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}
