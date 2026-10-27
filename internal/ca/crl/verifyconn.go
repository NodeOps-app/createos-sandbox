package crl

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
)

// VerifyConnectionFunc adapts a VerifyPeerCertificate callback into a
// tls.Config.VerifyConnection callback.
//
// Why both are needed: Go only calls VerifyPeerCertificate during a FULL
// handshake. On a resumed session (server-issued session tickets, or a
// client with a session cache) the peer certificate comes from the
// resumption state and VerifyPeerCertificate never fires — so a cert
// revoked after the first handshake keeps working for the ticket
// lifetime. VerifyConnection runs on both full and resumed handshakes,
// which closes that window without disabling resumption.
//
// Wire both at every mTLS site:
//
//	cfg.VerifyPeerCertificate = crlSource.VerifyPeerCertificate
//	cfg.VerifyConnection = crl.VerifyConnectionFunc(crlSource.VerifyPeerCertificate)
func VerifyConnectionFunc(verify func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error) func(tls.ConnectionState) error {
	if verify == nil {
		return nil
	}
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("no peer certificate")
		}
		raw := make([][]byte, 0, len(cs.PeerCertificates))
		for _, c := range cs.PeerCertificates {
			raw = append(raw, c.Raw)
		}
		return verify(raw, cs.VerifiedChains)
	}
}
