package hostproxy

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// buildClientHello builds a minimal TLS 1.2 ClientHello record with the
// given SNI hostname.
func buildClientHello(sni string) []byte {
	// Build extensions: just one server_name extension.
	//   extension = ext_type(2) + ext_len(2) + payload
	// server_name payload = list_len(2) + [name_type(1) + name_len(2) + name]
	nameBytes := []byte(sni)
	nameEntry := make([]byte, 0, 3+len(nameBytes))
	nameEntry = append(nameEntry, 0x00) // host_name
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(nameBytes)))
	nameEntry = append(nameEntry, lenBuf[:]...)
	nameEntry = append(nameEntry, nameBytes...)

	serverNamePayload := make([]byte, 0, 2+len(nameEntry))
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(nameEntry)))
	serverNamePayload = append(serverNamePayload, lenBuf[:]...)
	serverNamePayload = append(serverNamePayload, nameEntry...)

	ext := make([]byte, 0, 4+len(serverNamePayload))
	ext = append(ext, 0x00, 0x00) // ext type = server_name
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(serverNamePayload)))
	ext = append(ext, lenBuf[:]...)
	ext = append(ext, serverNamePayload...)

	extensions := make([]byte, 0, 2+len(ext))
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(ext)))
	extensions = append(extensions, lenBuf[:]...)
	extensions = append(extensions, ext...)

	// ClientHello body:
	//   version(2) + random(32) + session_id(1+0) + cipher_suites(2+2) +
	//   compression(1+1) + extensions
	body := make([]byte, 0, 64)
	body = append(body, 0x03, 0x03)             // TLS 1.2
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, 0x00)                   // session_id len = 0
	body = append(body, 0x00, 0x02, 0x00, 0x2f) // 1 cipher suite (TLS_RSA_WITH_AES_128_CBC_SHA)
	body = append(body, 0x01, 0x00)             // compression_methods: len=1, null
	body = append(body, extensions...)

	// handshake: type(1) + length(3) + body
	hs := make([]byte, 0, 4+len(body))
	hs = append(hs, 0x01) // ClientHello
	hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)

	// TLS record: type(1) + version(2) + length(2) + hs
	rec := make([]byte, 0, 5+len(hs))
	rec = append(rec, 0x16, 0x03, 0x01) // handshake, TLS 1.0 record version
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(hs)))
	rec = append(rec, lenBuf[:]...)
	rec = append(rec, hs...)
	return rec
}

// fakeConn adapts a byte slice to net.Conn by wrapping one side of a net.Pipe.
func pipeWith(b []byte) net.Conn {
	c1, c2 := net.Pipe()
	go func() {
		_, _ = c2.Write(b) // the reader side asserts on what it got
		c2.Close()
	}()
	return c1
}

func TestSniffHostname_TLS(t *testing.T) {
	hello := buildClientHello("example.com")
	conn := pipeWith(hello)
	defer conn.Close()

	host, peeked, err := SniffHostname(conn, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("SniffHostname: %v", err)
	}
	if host != "example.com" {
		t.Fatalf("host = %q, want example.com", host)
	}
	if len(peeked) == 0 {
		t.Fatalf("peeked buffer empty")
	}
}

func TestSniffHostname_HTTP(t *testing.T) {
	req := []byte("GET / HTTP/1.1\r\nHost: foo.bar:8080\r\nUser-Agent: x\r\n\r\n")
	conn := pipeWith(req)
	defer conn.Close()

	host, peeked, err := SniffHostname(conn, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("SniffHostname: %v", err)
	}
	if host != "foo.bar" {
		t.Fatalf("host = %q, want foo.bar", host)
	}
	if len(peeked) == 0 {
		t.Fatalf("peeked buffer empty")
	}
}

func TestSniffHostname_Garbage(t *testing.T) {
	conn := pipeWith([]byte("not http not tls just bytes\n\n"))
	defer conn.Close()

	host, _, err := SniffHostname(conn, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("SniffHostname: %v", err)
	}
	if host != "" {
		t.Fatalf("host = %q, want empty", host)
	}
}
