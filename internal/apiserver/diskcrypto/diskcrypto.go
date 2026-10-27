// Package diskcrypto protects disk credentials at rest in PostgreSQL.
// Control uses it when creating or updating a disk to AES-256-GCM encrypt
// the S3 credentials before writing disks.credentials, and decrypts that
// column when resolving a disk for sandbox create, attach, or resume.
//
// The operator-supplied disk_credential_key is symmetric and belongs only
// to control-plane processes that must read those database rows; machine
// hosts never receive it. After control decrypts a row, the separate
// cryptobox package seals the plaintext credentials to the destination
// host's public key for control-to-host transport. The destination host
// opens that transport envelope with its own private key.
//
// The persisted envelope uses AES-256-GCM with a fresh 12-byte nonce per
// encryption and a versioned JSON shape so a future key or algorithm
// migration can be introduced without confusing existing rows.
package diskcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

// EnvelopeVersion is the current encryption envelope format. Bumped only
// when on-disk shape changes (e.g. new KDF, new algorithm).
const EnvelopeVersion = 1

// KeyLen is the AES-256 key length in bytes.
const KeyLen = 32

// Envelope is the JSON shape persisted in disks.credentials.
type Envelope struct {
	V     int    `json:"v"`     // EnvelopeVersion
	Nonce string `json:"nonce"` // base64-std, 12 bytes
	CT    string `json:"ct"`    // base64-std, AES-GCM ciphertext+tag
}

// Cipher is a constructed AEAD around the operator-supplied key.
type Cipher struct {
	aead cipher.AEAD
}

// New constructs a Cipher from a raw 32-byte key. Returns an error on
// any length other than 32.
func New(key []byte) (*Cipher, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("diskcrypto: key length must be %d bytes, got %d", KeyLen, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("diskcrypto: aes new: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("diskcrypto: gcm new: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// LoadKeyFromFile reads a 32-byte key from disk. Accepts:
//   - raw 32-byte file (mode 0600 recommended)
//   - hex-encoded (64 chars)
//   - base64-std-encoded (44 chars including padding) or base64-url
//
// Whitespace and trailing newlines are trimmed before decoding.
func LoadKeyFromFile(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("diskcrypto: empty key path")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("diskcrypto: read key %s: %w", path, err)
	}
	return parseKey(raw)
}

// LoadKeyFromEnv resolves a key string (env or yaml) into 32 bytes.
// Identical decoder to LoadKeyFromFile so operators don't have to remember
// "is this the file path or the value?".
func LoadKeyFromEnv(value string) ([]byte, error) {
	if value == "" {
		return nil, errors.New("diskcrypto: empty key value")
	}
	return parseKey([]byte(value))
}

func parseKey(raw []byte) ([]byte, error) {
	// Strip trailing CR/LF/whitespace from file dumps.
	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) == 0 {
		return nil, errors.New("diskcrypto: key is empty after trim")
	}
	// Raw 32-byte file. Distinguish from base64 by length AND
	// presence of non-printable bytes — base64/hex are always printable
	// ASCII, so a length-32 buffer with any byte <0x20 or >0x7e is
	// definitely raw.
	if len(raw) == KeyLen {
		isPrintable := true
		for _, b := range raw {
			if b < 0x20 || b > 0x7e {
				isPrintable = false
				break
			}
		}
		if !isPrintable {
			out := make([]byte, KeyLen)
			copy(out, raw)
			return out, nil
		}
	}
	// Try hex first (longest unambiguous shape).
	if len(trimmed) == hex.EncodedLen(KeyLen) {
		if k, err := hex.DecodeString(trimmed); err == nil && len(k) == KeyLen {
			return k, nil
		}
	}
	// Try std-base64.
	if k, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(k) == KeyLen {
		return k, nil
	}
	// Try url-base64.
	if k, err := base64.RawURLEncoding.DecodeString(trimmed); err == nil && len(k) == KeyLen {
		return k, nil
	}
	if k, err := base64.URLEncoding.DecodeString(trimmed); err == nil && len(k) == KeyLen {
		return k, nil
	}
	// Last resort: maybe the file IS exactly 32 printable bytes. This
	// path is a legacy convenience — every prod deployment SHOULD use
	// hex (64 chars) or base64 (44 chars) so the file is unambiguously
	// machine-generated key material rather than a passphrase someone
	// typed. We keep accepting it because removing it would brick any
	// host that's been running on a typed key (the operator can't just
	// swap the file — the new value would fail to decrypt existing
	// `disks.credentials` rows, requiring a re-encrypt migration).
	//
	// We DO refuse the most obvious footgun — a key that's a single
	// byte repeated 32 times (e.g. "aaaaaaaa..." or "00000000...").
	// That's never deliberate; it's a placeholder someone forgot to
	// replace.
	//
	// And we loudly warn on every other printable-fallback hit so an
	// operator sees it in startup logs and can plan a migration to a
	// hex/base64-encoded key (procedure: dual-decrypt window, re-write
	// disks.credentials rows, then rotate the file).
	if len(trimmed) == KeyLen {
		// Reject repeated-byte placeholders outright.
		allSame := true
		first := trimmed[0]
		for i := 1; i < len(trimmed); i++ {
			if trimmed[i] != first {
				allSame = false
				break
			}
		}
		if allSame {
			return nil, fmt.Errorf("diskcrypto: key is %d copies of byte %q — clearly a placeholder, refusing to use as encryption key", KeyLen, first)
		}
		log.Warnf("diskcrypto: key file is %d printable ASCII bytes (looks like a typed passphrase, not a generated key). "+
			"Switch to hex (64 chars from `openssl rand -hex 32`) or base64 (`openssl rand -base64 32`). "+
			"The current value WILL still work; this warning fires once per process start.", KeyLen)
		return []byte(trimmed), nil
	}
	return nil, fmt.Errorf("diskcrypto: key must decode to %d bytes (got %d after trim)", KeyLen, len(trimmed))
}

// Encrypt wraps plaintext into a versioned JSON envelope.
func (c *Cipher) Encrypt(plaintext []byte) (json.RawMessage, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("diskcrypto: nonce read: %w", err)
	}
	ct := c.aead.Seal(nil, nonce, plaintext, nil)
	env := Envelope{
		V:     EnvelopeVersion,
		Nonce: base64.StdEncoding.EncodeToString(nonce),
		CT:    base64.StdEncoding.EncodeToString(ct),
	}
	return json.Marshal(env)
}

// Decrypt reverses Encrypt. Returns an error on tampering (GCM auth tag
// rejection), unknown version, or malformed envelope.
func (c *Cipher) Decrypt(envelope json.RawMessage) ([]byte, error) {
	var env Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return nil, fmt.Errorf("diskcrypto: envelope unmarshal: %w", err)
	}
	if env.V != EnvelopeVersion {
		return nil, fmt.Errorf("diskcrypto: unsupported envelope version %d", env.V)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("diskcrypto: nonce decode: %w", err)
	}
	if len(nonce) != c.aead.NonceSize() {
		return nil, fmt.Errorf("diskcrypto: nonce length %d != %d", len(nonce), c.aead.NonceSize())
	}
	ct, err := base64.StdEncoding.DecodeString(env.CT)
	if err != nil {
		return nil, fmt.Errorf("diskcrypto: ciphertext decode: %w", err)
	}
	plain, err := c.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("diskcrypto: open: %w", err)
	}
	return plain, nil
}
