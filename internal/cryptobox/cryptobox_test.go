package cryptobox

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func mustKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, priv
}

func TestRoundTrip(t *testing.T) {
	pub, priv := mustKeypair(t)
	want := []byte(`{"access_key":"AKIA...","secret_key":"shh"}`)

	env, err := Seal(pub, PurposeDiskCredentials, want)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	wire, err := env.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := UnmarshalEnvelope(wire)
	if err != nil {
		t.Fatalf("UnmarshalEnvelope: %v", err)
	}
	plain, err := Open(priv, PurposeDiskCredentials, got)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(plain, want) {
		t.Fatalf("plain mismatch:\n got: %s\nwant: %s", plain, want)
	}
}

func TestPurposeMismatchFails(t *testing.T) {
	pub, priv := mustKeypair(t)
	env, err := Seal(pub, PurposeDiskCredentials, []byte("hello"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	_, err = Open(priv, Purpose("createos/something-else/v1"), env)
	if err == nil {
		t.Fatal("Open succeeded with mismatched purpose; expected AEAD failure")
	}
}

func TestWrongRecipientFails(t *testing.T) {
	pub1, _ := mustKeypair(t)
	_, priv2 := mustKeypair(t)
	env, err := Seal(pub1, PurposeDiskCredentials, []byte("hello"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := Open(priv2, PurposeDiskCredentials, env); err == nil {
		t.Fatal("Open succeeded with wrong recipient key; expected failure")
	}
}

func TestTamperedCiphertextFails(t *testing.T) {
	pub, priv := mustKeypair(t)
	env, err := Seal(pub, PurposeDiskCredentials, []byte("hello world"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	env.Cipher[0] ^= 0xff
	if _, err := Open(priv, PurposeDiskCredentials, env); err == nil {
		t.Fatal("Open succeeded with tampered cipher; expected AEAD tag failure")
	}
}

func TestTamperedNonceFails(t *testing.T) {
	pub, priv := mustKeypair(t)
	env, err := Seal(pub, PurposeDiskCredentials, []byte("hi"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	env.Nonce[0] ^= 0xff
	if _, err := Open(priv, PurposeDiskCredentials, env); err == nil {
		t.Fatal("Open succeeded with tampered nonce; expected failure")
	}
}

func TestTamperedEphPubFails(t *testing.T) {
	pub, priv := mustKeypair(t)
	env, err := Seal(pub, PurposeDiskCredentials, []byte("hi"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	env.EphPub[0] ^= 0xff
	if _, err := Open(priv, PurposeDiskCredentials, env); err == nil {
		t.Fatal("Open succeeded with tampered eph_pub; expected failure")
	}
}

func TestUnknownVersionRejected(t *testing.T) {
	pub, priv := mustKeypair(t)
	env, err := Seal(pub, PurposeDiskCredentials, []byte("hi"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	env.V = 999
	if _, err := Open(priv, PurposeDiskCredentials, env); err == nil {
		t.Fatal("Open accepted unknown envelope version")
	}
}

func TestNonceUniqueness(t *testing.T) {
	pub, _ := mustKeypair(t)
	const N = 50
	seen := make(map[string]struct{}, N)
	for i := 0; i < N; i++ {
		env, err := Seal(pub, PurposeDiskCredentials, []byte("same payload"))
		if err != nil {
			t.Fatalf("Seal[%d]: %v", i, err)
		}
		key := string(env.Nonce) + string(env.EphPub)
		if _, dup := seen[key]; dup {
			t.Fatalf("nonce+ephPub collision at iteration %d — RNG broken?", i)
		}
		seen[key] = struct{}{}
	}
}

func TestRequiredArgs(t *testing.T) {
	pub, priv := mustKeypair(t)
	if _, err := Seal(pub, "", []byte("x")); err == nil {
		t.Fatal("Seal accepted empty purpose")
	}
	if _, err := Open(priv, "", &Envelope{V: 1}); err == nil {
		t.Fatal("Open accepted empty purpose")
	}
	if _, err := Open(priv, PurposeDiskCredentials, nil); err == nil {
		t.Fatal("Open accepted nil envelope")
	}
	short := ed25519.PublicKey(make([]byte, 5))
	if _, err := Seal(short, PurposeDiskCredentials, []byte("x")); err == nil {
		t.Fatal("Seal accepted short pubkey")
	}
}
