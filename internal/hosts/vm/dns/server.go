package dns

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// StubAddr is the link-local address the DNS stub binds on. VMs reach
	// it via their gateway (the host-side veth peer IP).
	StubAddr = "169.254.20.10:53"

	// Zone is the authoritative suffix served by the stub.
	Zone = "fc.local."

	// maxUDPSize is the maximum DNS response we send. All our responses are
	// simple single-A-record replies that fit well within 512 bytes.
	maxUDPSize = 512

	// forwardTimeout bounds each upstream query when relaying an out-of-zone
	// name. Kept short so a dead upstream fails over to the next quickly.
	forwardTimeout       = 3 * time.Second
	maxConcurrentQueries = 128
)

// DefaultUpstreams are the public recursive resolvers the stub forwards
// out-of-zone (non-fc.local) queries to. Mirrors the guest resolv.conf
// fallbacks set in network.go.
var DefaultUpstreams = []string{"1.1.1.1:53", "8.8.8.8:53"}

// Run starts the UDP DNS stub and blocks until ctx is cancelled.
// table is the shared name→IP map updated by the network reconciler.
// upstreams are the recursive resolvers out-of-zone names are forwarded to;
// empty falls back to DefaultUpstreams.
func Run(ctx context.Context, table *Table, upstreams []string) error {
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	slots := make(chan struct{}, maxConcurrentQueries)
	if len(upstreams) == 0 {
		upstreams = DefaultUpstreams
	}
	pc, err := net.ListenPacket("udp4", StubAddr)
	if err != nil {
		return err
	}
	log.WithContext(ctx).Infof("[dns-stub] listening on %s (zone %s, upstreams %v)", StubAddr, Zone, upstreams)

	go func() {
		<-ctx.Done()
		pc.Close()
	}()

	buf := make([]byte, 512)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.WithContext(ctx).Debugf("[dns-stub] read error: %v", err)
				continue
			}
		}
		select {
		case slots <- struct{}{}:
		default:
			continue // Bound work and sockets; clients may retry dropped queries.
		}
		srcIP := ""
		if ua, ok := addr.(*net.UDPAddr); ok && ua.IP != nil {
			srcIP = ua.IP.String()
		}
		// Copy the packet: buf is reused on the next ReadFrom, and out-of-zone
		// names are forwarded upstream (a blocking network call) in a
		// goroutine — otherwise one slow upstream stalls every other VM's query.
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		workers.Add(1)
		go func(pkt []byte, addr net.Addr, srcIP string) {
			defer workers.Done()
			defer func() { <-slots }()
			resp := handleQuerySafely(ctx, pkt, table, srcIP, upstreams)
			if resp != nil {
				_, _ = pc.WriteTo(resp, addr)
			}
		}(pkt, addr, srcIP)
	}
}

// handleQuerySafely is the packet trust boundary. Parser and encoder bounds
// checks are the primary protection; recover prevents any future malformed
// packet bug in this per-query goroutine from terminating machine host and
// every sandbox on the host.
func handleQuerySafely(ctx context.Context, pkt []byte, table *Table, srcIP string, upstreams []string) (resp []byte) {
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Errorf("[dns-stub] recovered malformed packet panic: %v", recovered)
			resp = nil
		}
	}()
	return handleQuery(ctx, pkt, table, srcIP, upstreams)
}

// handleQuery parses a DNS query and returns the response bytes, or nil to
// send nothing (malformed packet, unsupported opcode, etc.).
func handleQuery(ctx context.Context, pkt []byte, table *Table, srcIP string, upstreams []string) []byte {
	if len(pkt) < 12 {
		return nil
	}

	// DNS header fields.
	id := binary.BigEndian.Uint16(pkt[0:2])
	flags := binary.BigEndian.Uint16(pkt[2:4])
	qdCount := binary.BigEndian.Uint16(pkt[4:6])

	// Must be a standard query (QR=0, OPCODE=0).
	if flags&0x8000 != 0 { // QR bit set → it's a response, not a query
		return nil
	}
	if (flags>>11)&0xF != 0 { // OPCODE != 0 → not a standard query
		return notImpl(id, flags)
	}
	if qdCount == 0 {
		return nil
	}

	// Parse the first question.
	name, qtype, offset, ok := parseQuestion(pkt, 12)
	if !ok {
		return formatError(id, flags)
	}

	// Out-of-zone names must return REFUSED before anything else — NXDOMAIN
	// is authoritative and stops the resolver chain, breaking fallthrough to
	// upstream nameservers (1.1.1.1, etc.) in /etc/resolv.conf. This applies
	// to ALL qtypes (A, AAAA, etc.) — glibc's getaddrinfo issues parallel
	// A+AAAA, and if the AAAA gets NXDOMAIN here it short-circuits the
	// whole lookup even when the A succeeds upstream.
	stripName := strings.TrimSuffix(name, ".")
	zoneSuffix := "." + strings.TrimSuffix(Zone, ".")
	if !strings.HasSuffix(stripName, zoneSuffix) && stripName != "" {
		// Out-of-zone: forward to the upstream recursive resolvers and relay
		// the reply verbatim (its ID + question match the guest's query, so
		// the guest resolver accepts it). This makes the stub a complete
		// resolver — single-server tools like `dig` (which don't fall through
		// on REFUSED) now resolve public names too. On upstream failure we
		// still return REFUSED so glibc rotates to the next resolv.conf entry.
		if resp := forward(ctx, pkt, upstreams); resp != nil {
			return resp
		}
		return refused(id, flags, pkt[12:offset])
	}

	// We only serve A records. For any other in-zone qtype (notably AAAA
	// for the parallel A+AAAA glibc/Go issue):
	//   - if the name resolves (A would succeed) → NODATA (NOERROR, empty
	//     answer): "name exists, just no record of this type". Go's
	//     net.Resolver requires this — NXDOMAIN on AAAA is authoritative
	//     for the entire name (RFC 8020) and Go discards the parallel A
	//     response, breaking *any* Go binary doing peer-to-peer lookup
	//     (k3s, etcd, vault, consul, …). glibc is more forgiving.
	//   - if the name doesn't resolve at all → NXDOMAIN (real miss).
	ip := resolve(name, table, srcIP)
	if qtype != 1 && qtype != 255 {
		if ip != nil {
			return noData(id, flags, pkt[12:offset])
		}
		return nxdomain(id, flags, pkt[12:offset])
	}
	if ip == nil {
		return nxdomain(id, flags, pkt[12:offset])
	}
	return answer(id, flags, pkt[12:offset], ip)
}

// resolve looks up name in the table and returns a 4-byte IPv4, or nil.
// name is already lower-cased by parseQuestion. srcIP scopes alias lookups
// to networks the requester belongs to (cross-network → NXDOMAIN).
func resolve(name string, table *Table, srcIP string) net.IP {
	// Strip trailing dot.
	name = strings.TrimSuffix(name, ".")
	// Must end in ".fc.local".
	suffix := "." + strings.TrimSuffix(Zone, ".")
	if !strings.HasSuffix(name, suffix) {
		return nil
	}
	label := name[:len(name)-len(suffix)] // everything before ".fc.local"

	// Three forms:
	//   <sandbox_id>.fc.local       → one label, no dots
	//   <name>.fc.local             → one label, no dots (by VM name)
	//   <name>.<net_name>.fc.local  → two labels, one dot in label

	if !strings.Contains(label, ".") {
		// Single-label form: try the sandbox ID first (any membership),
		// then the user-facing VM name scoped to the requester's networks.
		if ipStr := table.LookupSandbox(label, srcIP); ipStr != "" {
			return net.ParseIP(ipStr).To4()
		}
		if ipStr := table.LookupBareName(label, srcIP); ipStr != "" {
			return net.ParseIP(ipStr).To4()
		}
		return nil
	}

	// Name form: split on first dot → vmName, networkName.
	dot := strings.IndexByte(label, '.')
	vmName := label[:dot]
	netName := label[dot+1:]
	ipStr := table.LookupName(vmName, netName, srcIP)
	if ipStr == "" {
		return nil
	}
	return net.ParseIP(ipStr).To4()
}

// forward relays an out-of-zone query to the upstream resolvers and returns
// the first reply, verbatim. Tries each upstream in order; returns nil if all
// fail so the caller can fall back to REFUSED. The 4 KiB read buffer covers
// EDNS responses larger than the classic 512-byte limit.
func forward(ctx context.Context, pkt []byte, upstreams []string) []byte {
	for _, up := range upstreams {
		if ctx.Err() != nil {
			return nil
		}
		dialer := net.Dialer{Timeout: forwardTimeout}
		c, err := dialer.DialContext(ctx, "udp", up)
		if err != nil {
			continue
		}
		stop := context.AfterFunc(ctx, func() { c.Close() })
		_ = c.SetDeadline(time.Now().Add(forwardTimeout))
		if _, err := c.Write(pkt); err != nil {
			stop()
			_ = c.Close()
			continue
		}
		buf := make([]byte, 4096)
		n, err := c.Read(buf)
		stop()
		_ = c.Close()
		if err != nil {
			continue
		}
		return buf[:n]
	}
	return nil
}

// ── DNS wire format helpers ───────────────────────────────────────────────

// parseQuestion reads the QNAME + QTYPE + QCLASS starting at offset in pkt.
// Returns (lower-cased FQDN, qtype, next-offset, ok).
func parseQuestion(pkt []byte, offset int) (string, uint16, int, bool) {
	qnameStart := offset
	var labels []string
	for {
		if offset >= len(pkt) {
			return "", 0, 0, false
		}
		length := int(pkt[offset])
		offset++
		if length == 0 {
			break
		}
		// DNS labels are at most 63 bytes; the two high bits are reserved for
		// compression/extended label types. We do not accept either in queries.
		// Checking only 0xC0 here previously treated 64..191 as literal lengths.
		if length > 63 {
			return "", 0, 0, false
		}
		if offset+length > len(pkt) {
			return "", 0, 0, false
		}
		labels = append(labels, strings.ToLower(string(pkt[offset:offset+length])))
		offset += length
	}
	// RFC 1035 caps the complete encoded QNAME, including label-length bytes
	// and the root terminator, at 255 bytes.
	if offset-qnameStart > 255 {
		return "", 0, 0, false
	}
	if offset+4 > len(pkt) {
		return "", 0, 0, false
	}
	qtype := binary.BigEndian.Uint16(pkt[offset : offset+2])
	// qclass := binary.BigEndian.Uint16(pkt[offset+2 : offset+4])
	offset += 4

	name := strings.Join(labels, ".") + "."
	return name, qtype, offset, true
}

func answer(id, qflags uint16, question []byte, ip net.IP) []byte {
	const answerRRSize = 16 // compressed NAME + TYPE + CLASS + TTL + RDLENGTH + IPv4
	required := 12 + len(question) + answerRRSize
	if required > maxUDPSize || ip.To4() == nil {
		return formatError(id, qflags)
	}
	resp := make([]byte, required)
	// Header: id, flags (QR=1, AA=1, RCODE=0), QDCOUNT=1, ANCOUNT=1.
	binary.BigEndian.PutUint16(resp[0:], id)
	binary.BigEndian.PutUint16(resp[2:], (qflags&0x0100)|0x8400) // QR+AA, preserve RD
	binary.BigEndian.PutUint16(resp[4:], 1)                      // QDCOUNT
	binary.BigEndian.PutUint16(resp[6:], 1)                      // ANCOUNT
	binary.BigEndian.PutUint16(resp[8:], 0)                      // NSCOUNT
	binary.BigEndian.PutUint16(resp[10:], 0)                     // ARCOUNT

	off := 12
	// Copy question section verbatim.
	off += copy(resp[off:], question)

	// Answer RR: pointer to question name (offset 12 = 0xC00C).
	resp[off] = 0xC0
	resp[off+1] = 0x0C
	off += 2
	binary.BigEndian.PutUint16(resp[off:], 1) // TYPE A
	off += 2
	binary.BigEndian.PutUint16(resp[off:], 1) // CLASS IN
	off += 2
	binary.BigEndian.PutUint32(resp[off:], 5) // TTL 5s (short: reconciler updates every 5s)
	off += 4
	binary.BigEndian.PutUint16(resp[off:], 4) // RDLENGTH
	off += 2
	off += copy(resp[off:], ip.To4())

	return resp[:off]
}

// noData returns NOERROR with an empty answer section — "the name
// exists, just no record of this type." Used for in-zone AAAA queries
// against names that have an A record; without this, Go's net.Resolver
// (parallel A+AAAA, RFC-8020 NXDOMAIN handling) discards the parallel
// A response and the lookup fails.
func noData(id, qflags uint16, question []byte) []byte {
	resp := make([]byte, 12+len(question))
	binary.BigEndian.PutUint16(resp[0:], id)
	// QR=1, AA=1, RCODE=0 (NOERROR), preserve RD.
	binary.BigEndian.PutUint16(resp[2:], (qflags&0x0100)|0x8400)
	binary.BigEndian.PutUint16(resp[4:], 1) // QDCOUNT
	copy(resp[12:], question)
	return resp
}

func nxdomain(id, qflags uint16, question []byte) []byte {
	resp := make([]byte, 12+len(question))
	binary.BigEndian.PutUint16(resp[0:], id)
	// QR=1, AA=1, RCODE=3 (NXDOMAIN), preserve RD.
	binary.BigEndian.PutUint16(resp[2:], (qflags&0x0100)|0x8403)
	binary.BigEndian.PutUint16(resp[4:], 1) // QDCOUNT
	copy(resp[12:], question)
	return resp
}

func notImpl(id, qflags uint16) []byte {
	resp := make([]byte, 12)
	binary.BigEndian.PutUint16(resp[0:], id)
	binary.BigEndian.PutUint16(resp[2:], (qflags&0x0100)|0x8404) // RCODE=4 NOTIMP
	return resp
}

func formatError(id, qflags uint16) []byte {
	resp := make([]byte, 12)
	binary.BigEndian.PutUint16(resp[0:], id)
	binary.BigEndian.PutUint16(resp[2:], (qflags&0x0100)|0x8401) // RCODE=1 FORMERR
	return resp
}

// refused returns a DNS REFUSED (RCODE=5) response. Used for out-of-zone
// names so glibc's resolver falls through to the next nameserver in
// resolv.conf. NXDOMAIN would be authoritative and stop the lookup chain.
func refused(id, qflags uint16, question []byte) []byte {
	resp := make([]byte, 12+len(question))
	binary.BigEndian.PutUint16(resp[0:], id)
	// QR=1, AA=0, RCODE=5 (REFUSED), preserve RD.
	binary.BigEndian.PutUint16(resp[2:], (qflags&0x0100)|0x8005)
	binary.BigEndian.PutUint16(resp[4:], 1) // QDCOUNT
	copy(resp[12:], question)
	return resp
}
