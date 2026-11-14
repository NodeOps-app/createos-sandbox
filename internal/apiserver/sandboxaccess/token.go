// Package sandboxaccess defines the opaque credential used to delegate
// control of exactly one sandbox. Persistence and route authorization live in
// their respective layers; this package owns only the token representation.
package sandboxaccess

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/NodeOps-app/createos-sandbox/internal/apiserver/userapikey"
)

const (
	Prefix         = "skp_sb_"
	randomByteSize = 32
)

var (
	ErrInvalidToken = errors.New("invalid sandbox access token")
	ErrHashDisabled = errors.New("sandbox access token hashing is not configured")
)

// Generate returns a URL-safe token carrying 256 bits of crypto/rand entropy.
func Generate() (string, error) {
	random := make([]byte, randomByteSize)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return Prefix + base64.RawURLEncoding.EncodeToString(random), nil
}

// Valid reports whether token has the canonical prefix and decodes to exactly
// 256 random bits. This prevents lookalike prefixes from entering local auth.
func Valid(token string) bool {
	if !strings.HasPrefix(token, Prefix) {
		return false
	}
	random, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, Prefix))
	return err == nil && len(random) == randomByteSize
}

// Hash validates token and derives the same HMAC-SHA256 digest used for
// ordinary API keys. Plaintext is never persisted.
func Hash(hasher *userapikey.Hasher, token string) ([]byte, error) {
	if !Valid(token) {
		return nil, ErrInvalidToken
	}
	digest := hasher.Hash(token)
	if len(digest) == 0 {
		return nil, ErrHashDisabled
	}
	return digest, nil
}

// Hint returns a non-secret identifier suitable for metadata and audit logs.
func Hint(token string) (string, error) {
	if !Valid(token) {
		return "", ErrInvalidToken
	}
	payload := strings.TrimPrefix(token, Prefix)
	return Prefix + payload[:4] + "..." + payload[len(payload)-4:], nil
}
