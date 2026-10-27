package hostproxy

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"time"
)

const sniffBufSize = 4096

// SniffHostname peeks up to 4KB of a connection's initial bytes to extract a
// domain the caller can match against rules. Returns "" if not found within
// a small timeout.
//
// Supported signals (first one wins):
//   - TLS ClientHello SNI
//   - HTTP request-line Host header
//
// The returned buffer contains the bytes already read from conn, which the
// caller must replay to the upstream connection before splicing.
func SniffHostname(conn net.Conn, timeout time.Duration) (host string, peeked []byte, err error) {
	if timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		defer func() { _ = conn.SetReadDeadline(time.Time{}) }() // clearing the deadline can only fail on an already-dead conn
	}
	buf := make([]byte, sniffBufSize)
	n, readErr := conn.Read(buf)
	if n == 0 {
		if readErr != nil {
			return "", nil, readErr
		}
		return "", nil, nil
	}
	peeked = buf[:n]
	if h, ok := parseTLSClientHelloSNI(peeked); ok {
		return strings.ToLower(h), peeked, nil
	}
	if h, ok := parseHTTPHost(peeked); ok {
		return strings.ToLower(h), peeked, nil
	}
	return "", peeked, nil
}

// parseTLSClientHelloSNI parses a raw TLS record containing a ClientHello
// and extracts the SNI server_name. Does NOT complete a handshake.
func parseTLSClientHelloSNI(b []byte) (string, bool) {
	// TLS record: type(1) + version(2) + length(2) + payload
	if len(b) < 5 {
		return "", false
	}
	if b[0] != 0x16 { // handshake
		return "", false
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if recLen <= 0 {
		return "", false
	}
	end := 5 + recLen
	if end > len(b) {
		end = len(b) // tolerate truncation; we'll bail out if we run off the end
	}
	p := b[5:end]
	// handshake: type(1) + length(3) + body
	if len(p) < 4 {
		return "", false
	}
	if p[0] != 0x01 { // ClientHello
		return "", false
	}
	// hsLen := (int(p[1])<<16)|(int(p[2])<<8)|int(p[3])
	p = p[4:]
	// version(2) + random(32)
	if len(p) < 2+32 {
		return "", false
	}
	p = p[2+32:]
	// session_id
	if len(p) < 1 {
		return "", false
	}
	sidLen := int(p[0])
	p = p[1:]
	if len(p) < sidLen {
		return "", false
	}
	p = p[sidLen:]
	// cipher_suites (2-byte len)
	if len(p) < 2 {
		return "", false
	}
	csLen := int(binary.BigEndian.Uint16(p[:2]))
	p = p[2:]
	if len(p) < csLen {
		return "", false
	}
	p = p[csLen:]
	// compression_methods (1-byte len)
	if len(p) < 1 {
		return "", false
	}
	cmLen := int(p[0])
	p = p[1:]
	if len(p) < cmLen {
		return "", false
	}
	p = p[cmLen:]
	// extensions (2-byte len)
	if len(p) < 2 {
		return "", false
	}
	extTotal := int(binary.BigEndian.Uint16(p[:2]))
	p = p[2:]
	if len(p) < extTotal {
		extTotal = len(p) // tolerate truncation
	}
	exts := p[:extTotal]
	for len(exts) >= 4 {
		extType := binary.BigEndian.Uint16(exts[:2])
		extLen := int(binary.BigEndian.Uint16(exts[2:4]))
		exts = exts[4:]
		if len(exts) < extLen {
			return "", false
		}
		payload := exts[:extLen]
		exts = exts[extLen:]
		if extType != 0x00 { // server_name
			continue
		}
		// server_name list
		if len(payload) < 2 {
			return "", false
		}
		listLen := int(binary.BigEndian.Uint16(payload[:2]))
		payload = payload[2:]
		if len(payload) < listLen {
			return "", false
		}
		list := payload[:listLen]
		for len(list) >= 3 {
			nameType := list[0]
			nameLen := int(binary.BigEndian.Uint16(list[1:3]))
			list = list[3:]
			if len(list) < nameLen {
				return "", false
			}
			name := list[:nameLen]
			list = list[nameLen:]
			if nameType == 0x00 && nameLen > 0 {
				return string(name), true
			}
		}
	}
	return "", false
}

// parseHTTPHost scans the buffer for an HTTP request-line + Host header.
// It returns the host (with any :port stripped).
func parseHTTPHost(b []byte) (string, bool) {
	// Cheap sanity: first line must look like METHOD SP URI SP HTTP/
	nl := bytes.IndexByte(b, '\n')
	if nl < 0 {
		return "", false
	}
	firstLine := b[:nl]
	if !looksLikeRequestLine(firstLine) {
		return "", false
	}
	rest := b[nl+1:]
	for {
		nl := bytes.IndexByte(rest, '\n')
		if nl < 0 {
			return "", false
		}
		line := rest[:nl]
		// strip trailing \r
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if len(line) == 0 {
			return "", false // end of headers without Host
		}
		// case-insensitive prefix "host:"
		if len(line) >= 5 && (line[0] == 'H' || line[0] == 'h') &&
			(line[1] == 'o' || line[1] == 'O') &&
			(line[2] == 's' || line[2] == 'S') &&
			(line[3] == 't' || line[3] == 'T') &&
			line[4] == ':' {
			v := strings.TrimSpace(string(line[5:]))
			// strip :port
			if idx := strings.LastIndex(v, ":"); idx > 0 {
				// only strip if the tail is all digits (so IPv6 literals would
				// need brackets, which is fine for our purpose)
				tail := v[idx+1:]
				allDigits := len(tail) > 0
				for _, r := range tail {
					if r < '0' || r > '9' {
						allDigits = false
						break
					}
				}
				if allDigits {
					v = v[:idx]
				}
			}
			return v, v != ""
		}
		rest = rest[nl+1:]
	}
}

func looksLikeRequestLine(line []byte) bool {
	// has " HTTP/" near the end
	if !bytes.Contains(line, []byte(" HTTP/")) {
		return false
	}
	// first token all uppercase letters
	sp := bytes.IndexByte(line, ' ')
	if sp <= 0 {
		return false
	}
	for _, c := range line[:sp] {
		if c < 'A' || c > 'Z' {
			return false
		}
	}
	return true
}
