package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// DefaultExpiry is the JWT lifetime createos mints. Short enough that a
// leaked token has limited replay value, long enough that small clock
// skews and slow networks don't kill legitimate calls.
const DefaultExpiry = 60 * time.Second

// SkewLeeway backdates minted nbf and allows verification within five seconds
// after exp or before nbf. It does not cap the lifetime of externally built claims.
const SkewLeeway = 5 * time.Second

// Signer mints JWTs for one actor. Safe for concurrent use provided callers
// do not mutate the private-key slice supplied to NewSigner.
type Signer struct {
	priv ed25519.PrivateKey
	kid  string // "<role>:<id>", e.g. "host:fc-vm-1"
}

// NewSigner returns a Signer that stamps every JWT with iss=kid and
// signs with priv.
func NewSigner(priv ed25519.PrivateKey, kid string) *Signer {
	return &Signer{priv: priv, kid: kid}
}

// PublicKey returns the signer's Ed25519 public key.
func (s *Signer) PublicKey() ed25519.PublicKey {
	return s.priv.Public().(ed25519.PublicKey)
}

// KID returns the signer's identity ("<role>:<id>").
func (s *Signer) KID() string { return s.kid }

// Sign mints a JWT carrying just identity (iss=kid), audience, and an
// optional sub. iat/nbf/exp/jti are stamped automatically.
func (s *Signer) Sign(aud, sub string) (string, error) {
	now := time.Now().UTC()
	claims := Claims{
		Iss: s.kid,
		Sub: sub,
		Aud: aud,
		Iat: now.Unix(),
		Nbf: now.Add(-SkewLeeway).Unix(),
		Exp: now.Add(DefaultExpiry).Unix(),
		Jti: newJTI(),
	}
	return s.sign(claims)
}

// SignFor mints identity, audience, validity, and jti claims plus uid.
// It signs the supplied user ID without validating that identity.
func (s *Signer) SignFor(aud, uid string) (string, error) {
	now := time.Now().UTC()
	claims := Claims{
		Iss:    s.kid,
		Aud:    aud,
		Iat:    now.Unix(),
		Nbf:    now.Add(-SkewLeeway).Unix(),
		Exp:    now.Add(DefaultExpiry).Unix(),
		Jti:    newJTI(),
		UserID: uid,
	}
	return s.sign(claims)
}

// SignProxy mints a token with Role="proxy" and the supplied audience.
// The verifier does not enforce role permissions; callers must do so.
func (s *Signer) SignProxy(aud string) (string, error) {
	now := time.Now().UTC()
	claims := Claims{
		Iss:  s.kid,
		Aud:  aud,
		Iat:  now.Unix(),
		Nbf:  now.Add(-SkewLeeway).Unix(),
		Exp:  now.Add(DefaultExpiry).Unix(),
		Jti:  newJTI(),
		Role: "proxy",
	}
	return s.sign(claims)
}

// SignClaims is the escape-hatch variant that signs an already-built Claims.
// Useful for tests that need to mint expired/future-dated tokens. Production
// code should call Sign.
func (s *Signer) SignClaims(c Claims) (string, error) {
	return s.sign(c)
}

func (s *Signer) sign(c Claims) (string, error) {
	header := map[string]string{
		"alg": "EdDSA",
		"typ": "JWT",
		"kid": s.kid,
	}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	pb, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}
	encoded := b64encode(hb) + "." + b64encode(pb)
	sig := ed25519.Sign(s.priv, []byte(encoded))
	return encoded + "." + b64encode(sig), nil
}

func b64encode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func newJTI() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
