package sandboxaccess

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/NodeOps-app/createos-sandbox/internal/apiserver/userapikey"
)

func TestGenerateProducesUniqueCanonicalTokens(t *testing.T) {
	first, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	second, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("Generate returned the same token twice")
	}
	for _, token := range []string{first, second} {
		if !strings.HasPrefix(token, Prefix) {
			t.Fatalf("token %q does not have prefix %q", token, Prefix)
		}
		if !Valid(token) {
			t.Fatalf("generated token %q is not valid", token)
		}
	}
}

func TestValidRejectsMalformedTokens(t *testing.T) {
	valid, err := Generate()
	if err != nil {
		t.Fatal(err)
	}

	tests := []string{
		"",
		"skp_" + strings.TrimPrefix(valid, Prefix),
		Prefix,
		Prefix + "not-base64!",
		valid[:len(valid)-1],
		valid + "A",
	}
	for _, token := range tests {
		if Valid(token) {
			t.Errorf("Valid(%q) = true; want false", token)
		}
	}
}

func TestHashUsesConfiguredPepper(t *testing.T) {
	token, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	pepperA := userapikey.NewHasher(bytes.Repeat([]byte{0x11}, 32))
	pepperB := userapikey.NewHasher(bytes.Repeat([]byte{0x22}, 32))

	first, err := Hash(pepperA, token)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Hash(pepperA, token)
	if err != nil {
		t.Fatal(err)
	}
	other, err := Hash(pepperB, token)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, again) {
		t.Fatal("same token and pepper produced different hashes")
	}
	if bytes.Equal(first, other) {
		t.Fatal("different peppers produced the same hash")
	}
	if len(first) != 32 {
		t.Fatalf("hash length = %d; want 32", len(first))
	}
}

func TestHashRejectsInvalidTokenAndDisabledHasher(t *testing.T) {
	configured := userapikey.NewHasher(bytes.Repeat([]byte{0x11}, 32))
	if _, err := Hash(configured, "not-a-sandbox-token"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("invalid token error = %v; want %v", err, ErrInvalidToken)
	}

	token, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Hash(userapikey.NewHasher(nil), token); !errors.Is(err, ErrHashDisabled) {
		t.Fatalf("disabled hasher error = %v; want %v", err, ErrHashDisabled)
	}
}

func TestHintIsSafeAndStable(t *testing.T) {
	token, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	hint, err := Hint(token)
	if err != nil {
		t.Fatal(err)
	}
	payload := strings.TrimPrefix(token, Prefix)
	want := Prefix + payload[:4] + "..." + payload[len(payload)-4:]
	if hint != want {
		t.Fatalf("Hint() = %q; want %q", hint, want)
	}
	if hint == token || strings.Contains(hint, payload) {
		t.Fatal("hint exposes the complete token payload")
	}

	if _, err := Hint("invalid"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("invalid hint error = %v; want %v", err, ErrInvalidToken)
	}
}
