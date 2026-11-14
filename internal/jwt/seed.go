// Package jwt implements Ed25519-signed JWTs with a fixed claims shape and
// issuer-key lookup. It provides signing, validation, and key-file helpers;
// callers choose the accepted signers and enforce resource authorization.
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

// LoadOrGenerateSeed loads a raw 32-byte Ed25519 seed, or generates and writes
// one when the file is absent. New files use mode 0600; existing files receive
// a best-effort mode correction. The caller owns parent-directory permissions
// and must serialize initialization if multiple processes share the path.
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
	// Attempt to restore owner-only read/write permissions on existing files.
	// Successful corrections and read-only filesystem failures are silent.
	enforceKeyFilePerms(path)
	return ed25519.NewKeyFromSeed(seed), nil
}

// enforceKeyFilePerms attempts chmod 0600 whenever the current mode differs.
// Stat failures and EROFS are ignored; other chmod failures are logged. It
// neither changes ownership nor rejects loading a key whose mode cannot change.
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

// LoadPublicKey reads a raw 32-byte Ed25519 public key from path.
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
