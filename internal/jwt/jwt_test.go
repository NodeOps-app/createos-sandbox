package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func mustKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func resolverFor(priv ed25519.PrivateKey, kid string) PublicKeyResolver {
	pub := priv.Public().(ed25519.PublicKey)
	return func(k string) (ed25519.PublicKey, error) {
		if k == kid {
			return pub, nil
		}
		return nil, nil
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	priv := mustKey(t)
	const kid = "host:fc-vm-1"
	s := NewSigner(priv, kid)
	tok, err := s.Sign(AudControl, "fc-vm-1")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	v := &Verifier{Resolve: resolverFor(priv, kid)}
	c, err := v.VerifyExpect(tok, AudControl)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if c.Iss != kid {
		t.Errorf("iss=%q want=%q", c.Iss, kid)
	}
	if c.Aud != AudControl {
		t.Errorf("aud mismatch: %+v", c)
	}
}

func TestTamperedPayloadRejected(t *testing.T) {
	priv := mustKey(t)
	s := NewSigner(priv, "host:a")
	tok, _ := s.Sign(AudHost, "sb_xyz")

	parts := strings.SplitN(tok, ".", 3)
	if len(parts) != 3 {
		t.Fatal("expected 3 segments")
	}
	tampered := parts[0] + "." + parts[1][:len(parts[1])-1] + "X" + "." + parts[2]
	v := &Verifier{Resolve: resolverFor(priv, "host:a")}
	if _, err := v.Verify(tampered); err == nil {
		t.Fatal("expected verify to fail on tampered payload")
	}
}

func TestUnknownKidRejected(t *testing.T) {
	priv := mustKey(t)
	s := NewSigner(priv, "ingress:ghost")
	tok, _ := s.Sign(AudHost, "sb_xyz")
	v := &Verifier{Resolve: resolverFor(priv, "host:other")} // wrong kid in resolver
	if _, err := v.Verify(tok); err == nil {
		t.Fatal("expected verify to fail on unknown kid")
	}
}

func TestExpired(t *testing.T) {
	priv := mustKey(t)
	s := NewSigner(priv, "host:a")
	now := time.Now().UTC().Unix()
	tok, _ := s.SignClaims(Claims{
		Iss: "host:a", Aud: AudControl, Sub: "fc-vm-1",
		Iat: now - 600, Nbf: now - 600, Exp: now - 60, Jti: "deadbeef",
	})
	v := &Verifier{Resolve: resolverFor(priv, "host:a")}
	if _, err := v.Verify(tok); err == nil {
		t.Fatal("expected verify to fail on expired token")
	}
}

func TestMissingExpiryRejected(t *testing.T) {
	priv := mustKey(t)
	s := NewSigner(priv, "builder:test")
	now := time.Now().UTC().Unix()
	tok, err := s.SignClaims(Claims{
		Iss: "builder:test", Aud: AudControl, Sub: "tpl_test",
		Iat: now, Nbf: now - 1, Jti: "missing-exp",
	})
	if err != nil {
		t.Fatal(err)
	}
	v := &Verifier{Resolve: resolverFor(priv, "builder:test")}
	if _, err := v.Verify(tok); err == nil || !strings.Contains(err.Error(), "exp") {
		t.Fatalf("expected missing expiry to be rejected, got %v", err)
	}
}

func TestNotYetValid(t *testing.T) {
	priv := mustKey(t)
	s := NewSigner(priv, "host:a")
	now := time.Now().UTC().Unix()
	tok, _ := s.SignClaims(Claims{
		Iss: "host:a", Aud: AudControl, Sub: "fc-vm-1",
		Iat: now, Nbf: now + 600, Exp: now + 660, Jti: "deadbeef",
	})
	v := &Verifier{Resolve: resolverFor(priv, "host:a")}
	if _, err := v.Verify(tok); err == nil {
		t.Fatal("expected verify to fail on nbf in the future")
	}
}

func TestKidIssMismatchRejected(t *testing.T) {
	priv := mustKey(t)
	s := NewSigner(priv, "host:a")
	c := Claims{
		Iss: "host:other", Aud: AudControl, Sub: "fc-vm-1",
		Iat: time.Now().Unix(), Nbf: time.Now().Add(-5 * time.Second).Unix(),
		Exp: time.Now().Add(60 * time.Second).Unix(), Jti: "x",
	}
	tok, err := s.SignClaims(c) // signed with kid=host:a (header) but iss=host:other (payload)
	if err != nil {
		t.Fatal(err)
	}
	v := &Verifier{Resolve: resolverFor(priv, "host:a")}
	if _, err := v.Verify(tok); err == nil {
		t.Fatal("expected verify to fail on kid/iss mismatch")
	}
}

func TestVerifyExpectWrongAud(t *testing.T) {
	priv := mustKey(t)
	s := NewSigner(priv, "host:a")
	tok, _ := s.Sign(AudControl, "fc-vm-1")
	v := &Verifier{Resolve: resolverFor(priv, "host:a")}
	if _, err := v.VerifyExpect(tok, AudHost); err == nil {
		t.Fatal("expected wrong aud to fail")
	}
}

func TestTokenIsCompact(t *testing.T) {
	// Sanity: a fresh token should fit comfortably in an Authorization
	// header. We don't have a hard SLA, but flag if it ever balloons.
	priv := mustKey(t)
	s := NewSigner(priv, "host:fc-vm-1")
	tok, _ := s.Sign(AudControl, "fc-vm-1")
	if got := len(tok); got > 400 {
		t.Errorf("JWT len=%d, expected ≤ 400 (drift check — minimal claims should keep it bounded)", got)
	}
}
