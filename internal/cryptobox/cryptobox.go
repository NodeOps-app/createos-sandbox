// Package cryptobox seals small payloads to a recipient identified by their
// Ed25519 public key, so confidentiality survives transmission over a
// plaintext channel.
//
// Callers must authenticate the recipient key and the sender separately.
// Encryption alone does not prove who sent an envelope or prevent replay.
//
// Construction:
//   - Convert the recipient's Ed25519 key material to X25519.
//   - Generate a fresh ephemeral X25519 keypair and derive a shared secret
//     against the recipient public key. HKDF-SHA256 derives the
//     ChaCha20-Poly1305 key.
//   - Send the ephemeral public key, nonce, and ciphertext. This does not
//     provide forward secrecy against compromise of the recipient private
//     key: that key and a captured envelope recover the shared secret.
//
// Domain separation:
//   - Every Seal/Open call takes a Purpose string. Two messages with
//     identical (sender, recipient, plaintext) but different purposes
//     produce different ciphertext and CANNOT decrypt each other. This
//     is how you safely add new use cases without worrying that a
//     captured "disk creds" envelope could be replayed as a "config
//     blob" envelope (or vice versa).
//   - Pick a stable, human-readable Purpose per use case and never
//     change it. Each well-known purpose has a constant below.
//
// Wire format is versioned (Envelope.V); receivers MUST reject any
// version they don't recognise. Today there is one: EnvelopeVersion = 1.
package cryptobox

import (
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// EnvelopeVersion is the only wire version recognised today. Bump only
// for incompatible changes (algorithm swap, AAD shape change, etc.).
const EnvelopeVersion = 1

// Purpose strings bind a sealed envelope to a specific use case so the
// derived symmetric key, and thus the ciphertext, is unique per
// purpose. Add a new constant per new message type; never reuse one.
//
// Rule of thumb: pick a short, stable identifier that names the secret
// being carried, not the route it travels. "disk-credentials" not
// "control-to-host-attach".
const (
	PurposeDiskCredentials Purpose = "createos/disk-credentials/v1"
)

// Purpose tags a Seal/Open call. It MUST be the same on both ends.
type Purpose string

// Envelope is the JSON shape on the wire. Stable across implementations.
type Envelope struct {
	V      int    `json:"v"`       // EnvelopeVersion; receivers reject unknown values
	EphPub []byte `json:"eph_pub"` // 32 bytes; sender's throwaway X25519 pub
	Nonce  []byte `json:"nonce"`   // 12 bytes; random per Seal
	Cipher []byte `json:"cipher"`  // ChaCha20-Poly1305 ciphertext + 16-byte tag
}

// Marshal returns the wire bytes (compact JSON).
func (e *Envelope) Marshal() ([]byte, error) { return json.Marshal(e) }

// UnmarshalEnvelope decodes wire bytes and validates structural fields
// (version, lengths). Cryptographic validity is verified by Open.
func UnmarshalEnvelope(b []byte) (*Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, fmt.Errorf("cryptobox: envelope decode: %w", err)
	}
	if e.V != EnvelopeVersion {
		return nil, fmt.Errorf("cryptobox: unsupported envelope version %d", e.V)
	}
	if len(e.EphPub) != curve25519.PointSize {
		return nil, fmt.Errorf("cryptobox: bad eph_pub length %d", len(e.EphPub))
	}
	if len(e.Nonce) != chacha20poly1305.NonceSize {
		return nil, fmt.Errorf("cryptobox: bad nonce length %d", len(e.Nonce))
	}
	if len(e.Cipher) < chacha20poly1305.Overhead {
		return nil, fmt.Errorf("cryptobox: bad cipher length %d", len(e.Cipher))
	}
	return &e, nil
}

// Seal encrypts plaintext to the recipient identified by their Ed25519
// public key. The envelope is JSON-serializable; sender authentication and
// replay protection remain the caller's responsibility.
//
// Open must be called with the same purpose; mismatched purposes
// produce different symmetric keys and decryption fails closed.
func Seal(recipientEd25519Pub ed25519.PublicKey, p Purpose, plaintext []byte) (*Envelope, error) {
	if p == "" {
		return nil, errors.New("cryptobox: purpose is required")
	}
	if len(recipientEd25519Pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("cryptobox: recipient pubkey must be %d bytes, got %d",
			ed25519.PublicKeySize, len(recipientEd25519Pub))
	}
	recipientX25519Pub, err := ed25519PubToX25519(recipientEd25519Pub)
	if err != nil {
		return nil, fmt.Errorf("cryptobox: convert recipient pubkey: %w", err)
	}

	// Ephemeral keypair, random per message. The local private-key buffer is
	// cleared after successful ECDH; this is not a guarantee of zeroization.
	var ephPriv [curve25519.ScalarSize]byte
	if _, err := io.ReadFull(rand.Reader, ephPriv[:]); err != nil {
		return nil, fmt.Errorf("cryptobox: read randomness: %w", err)
	}
	ephPub, err := curve25519.X25519(ephPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("cryptobox: derive ephemeral pub: %w", err)
	}

	shared, err := curve25519.X25519(ephPriv[:], recipientX25519Pub)
	if err != nil {
		return nil, fmt.Errorf("cryptobox: ecdh: %w", err)
	}
	for i := range ephPriv {
		ephPriv[i] = 0
	}

	aead, err := newAEAD(shared, ephPub, recipientX25519Pub, p)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("cryptobox: nonce: %w", err)
	}
	ct := aead.Seal(nil, nonce, plaintext, nil)
	return &Envelope{
		V:      EnvelopeVersion,
		EphPub: ephPub,
		Nonce:  nonce,
		Cipher: ct,
	}, nil
}

// Open decrypts an envelope sealed by Seal. recipientEd25519Priv is the
// full 64-byte Ed25519 private key, not a raw 32-byte seed. Conversion to
// X25519 happens internally. Validate wire envelopes with UnmarshalEnvelope
// before calling Open.
//
// Purpose mismatches surface as a generic Open error — the AEAD tag
// fails. Don't try to "recover" by guessing the right purpose: that's a
// configuration bug, not a transient failure.
func Open(recipientEd25519Priv ed25519.PrivateKey, p Purpose, env *Envelope) ([]byte, error) {
	if env == nil {
		return nil, errors.New("cryptobox: nil envelope")
	}
	if p == "" {
		return nil, errors.New("cryptobox: purpose is required")
	}
	if env.V != EnvelopeVersion {
		return nil, fmt.Errorf("cryptobox: unsupported envelope version %d", env.V)
	}
	if len(recipientEd25519Priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("cryptobox: recipient privkey must be %d bytes, got %d",
			ed25519.PrivateKeySize, len(recipientEd25519Priv))
	}
	recipientX25519Priv := ed25519PrivToX25519(recipientEd25519Priv)
	recipientX25519Pub, err := curve25519.X25519(recipientX25519Priv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("cryptobox: derive recipient pub: %w", err)
	}
	shared, err := curve25519.X25519(recipientX25519Priv, env.EphPub)
	if err != nil {
		return nil, fmt.Errorf("cryptobox: ecdh: %w", err)
	}
	for i := range recipientX25519Priv {
		recipientX25519Priv[i] = 0
	}
	aead, err := newAEAD(shared, env.EphPub, recipientX25519Pub, p)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, env.Nonce, env.Cipher, nil)
	if err != nil {
		return nil, fmt.Errorf("cryptobox: open: %w", err)
	}
	return plain, nil
}

// newAEAD derives a per-message ChaCha20-Poly1305 key from the shared
// ECDH point. The purpose plus both public keys go into HKDF's info
// parameter — domain-separating by recipient pubkey AND by use case.
func newAEAD(shared, ephPub, recipientPub []byte, p Purpose) (cipher.AEAD, error) {
	info := make([]byte, 0, len(p)+1+2*curve25519.PointSize)
	info = append(info, []byte(p)...)
	info = append(info, 0)
	info = append(info, ephPub...)
	info = append(info, recipientPub...)
	r := hkdf.New(sha256.New, shared, nil, info)
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("cryptobox: hkdf: %w", err)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("cryptobox: aead: %w", err)
	}
	return aead, nil
}

// ed25519PrivToX25519 converts the Ed25519 seed into the matching X25519
// scalar — SHA-512(seed)[0:32] then standard clamp. Canonical conversion
// used by libsodium and golang.org/x/crypto.
func ed25519PrivToX25519(priv ed25519.PrivateKey) []byte {
	seed := priv.Seed()
	h := sha512.Sum512(seed)
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	return h[:32]
}

// ed25519PubToX25519 converts an Edwards25519 public key into the
// matching Montgomery X25519 public key. The field math is
// u = (1+y)/(1-y) mod p, computed in extended coordinates as
// u = (Z+Y)/(Z-Y).
func ed25519PubToX25519(pub ed25519.PublicKey) ([]byte, error) {
	p, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return nil, fmt.Errorf("decode edwards pubkey: %w", err)
	}
	_, Y, Z, _ := p.ExtendedCoordinates()
	num := new(field.Element).Add(Z, Y)
	den := new(field.Element).Subtract(Z, Y)
	den.Invert(den)
	u := new(field.Element).Multiply(num, den)
	return u.Bytes(), nil
}

// Silence the "imported and not used" linter while keeping hash.Hash
// in scope for any future swap to a hashable HKDF salt.
var _ hash.Hash = sha256.New()
