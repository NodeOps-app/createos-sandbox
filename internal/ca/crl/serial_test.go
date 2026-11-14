package crl

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

type serialTestTransport func(*http.Request) (*http.Response, error)

func (f serialTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRevocationSerialRepresentations(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := func(serial int64) *x509.Certificate {
		t.Helper()
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	for _, serial := range []int64{0xabc, 0xabcd, 1} {
		revoked, allowed := certificate(serial), certificate(serial+1)
		canonical := revoked.SerialNumber.Text(16)
		for _, stored := range []string{canonical, "0" + canonical, "000" + canonical, " 0X00" + strings.ToUpper(canonical) + " "} {
			t.Run(stored, func(t *testing.T) {
				client := &http.Client{Transport: serialTestTransport(func(*http.Request) (*http.Response, error) {
					body := fmt.Sprintf(`{"status":"success","data":{"revoked":[{"serial":%q}]}}`, stored)
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
				})}
				f := New("https://control.example.test", client)
				if err := f.Refresh(context.Background()); err != nil {
					t.Fatal(err)
				}
				// Local.refresh applies this same normalization to ledger rows.
				l := &Local{revoked: map[string]struct{}{normalizeSerial(stored): {}}}
				for name, verify := range map[string]func([][]byte, [][]*x509.Certificate) error{"fetcher": f.VerifyPeerCertificate, "local": l.VerifyPeerCertificate} {
					if err := verify([][]byte{revoked.Raw}, nil); err == nil {
						t.Errorf("%s accepted revoked certificate", name)
					}
					if err := verify([][]byte{allowed.Raw}, nil); err != nil {
						t.Errorf("%s rejected unrelated certificate: %v", name, err)
					}
					if err := verify(nil, nil); err == nil {
						t.Errorf("%s accepted missing certificate", name)
					}
					if err := verify([][]byte{[]byte("invalid")}, nil); err == nil {
						t.Errorf("%s accepted malformed certificate", name)
					}
					if err := VerifyConnectionFunc(verify)(tls.ConnectionState{DidResume: true, PeerCertificates: []*x509.Certificate{revoked}}); err == nil {
						t.Errorf("%s accepted revoked resumed session", name)
					}
				}
			})
		}
	}
}
