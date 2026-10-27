package agent

// Minimal RTNETLINK client — stdlib only, enough for the agent's needs:
//   - flush all IPv4 addrs on an interface
//   - add an IPv4 addr with prefix
//   - delete the default IPv4 route
//   - add a default IPv4 route via gateway
//
// Why not call `ip` via exec: each busybox fork+execve is 10–25 ms on a
// shared-CPU cloud VM; we do four of them per snapshot restore. Netlink
// is a few hundred microseconds for the whole sequence. The tradeoff is
// ~150 lines of bit-packing here vs. saving ~80 ms off every spawn.
//
// Uses only the stdlib `syscall` package (no golang.org/x/sys, no
// github.com/vishvananda/netlink) so `make check-agent` stays green.

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// netlinkApply flushes existing IPv4 addrs on eth0, sets the new addr,
// and replaces the default IPv4 route in one batch of netlink sends.
// Uses NLM_F_REPLACE semantics where supported so add/replace collapses
// into a single round-trip.
func netlinkApply(ipStr string, prefix int, gwStr string) error {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return fmt.Errorf("invalid ip %q", ipStr)
	}
	gw := net.ParseIP(gwStr).To4()
	if gw == nil {
		return fmt.Errorf("invalid gateway %q", gwStr)
	}
	iface, err := net.InterfaceByName("eth0")
	if err != nil {
		return fmt.Errorf("eth0: %w", err)
	}
	c, err := dialNetlink()
	if err != nil {
		return err
	}
	defer c.close()

	if err := c.flushAddrs(iface.Index); err != nil {
		return fmt.Errorf("flush: %w", err)
	}
	if err := c.addAddr(iface.Index, ip, prefix); err != nil {
		return fmt.Errorf("add addr: %w", err)
	}
	// Best-effort delete of the prior default; ignore ENOENT etc.
	_ = c.delDefaultRoute()
	if err := c.addDefaultRoute(gw, iface.Index); err != nil {
		return fmt.Errorf("add default route: %w", err)
	}
	return nil
}

// ─── transport ────────────────────────────────────────────────────────

type nlConn struct {
	fd  int
	seq uint32
}

func dialNetlink() (*nlConn, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return &nlConn{fd: fd}, nil
}

func (c *nlConn) close() { syscall.Close(c.fd) }

// request sends a single netlink message and reads replies until NLMSG_DONE
// or an error/ACK is seen. ACK replies with zero error are treated as OK.
// replies is invoked for each RTM_NEWADDR reply (used by flushAddrs).
func (c *nlConn) request(msgType uint16, flags uint16, body []byte, replies func(hdr *syscall.NlMsghdr, data []byte) error) error {
	c.seq++
	hdrLen := syscall.SizeofNlMsghdr
	total := hdrLen + len(body)
	buf := make([]byte, total)
	hdr := (*syscall.NlMsghdr)(unsafe.Pointer(&buf[0]))
	hdr.Len = uint32(total)
	hdr.Type = msgType
	hdr.Flags = flags
	hdr.Seq = c.seq
	hdr.Pid = 0
	copy(buf[hdrLen:], body)
	if err := syscall.Sendto(c.fd, buf, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}
	rbuf := make([]byte, 8192)
	for {
		n, _, err := syscall.Recvfrom(c.fd, rbuf, 0)
		if err != nil {
			return err
		}
		msgs, err := syscall.ParseNetlinkMessage(rbuf[:n])
		if err != nil {
			return err
		}
		for _, m := range msgs {
			switch m.Header.Type {
			case syscall.NLMSG_DONE:
				return nil
			case syscall.NLMSG_ERROR:
				if len(m.Data) < 4 {
					return fmt.Errorf("short NLMSG_ERROR")
				}
				errno := int32(binary.LittleEndian.Uint32(m.Data[:4]))
				if errno == 0 {
					return nil // ACK
				}
				return syscall.Errno(-errno)
			default:
				if replies != nil {
					if err := replies(&m.Header, m.Data); err != nil {
						return err
					}
				}
			}
		}
		// Non-dump request without DONE/ACK shouldn't happen for our ops.
		if flags&syscall.NLM_F_DUMP == 0 {
			return nil
		}
	}
}

// ─── address ops ──────────────────────────────────────────────────────

// ifaddrmsg per include/uapi/linux/if_addr.h
type ifaddrmsg struct {
	Family    uint8
	Prefixlen uint8
	Flags     uint8
	Scope     uint8
	Index     uint32
}

const (
	IFA_ADDRESS = 1
	IFA_LOCAL   = 2

	RTM_NEWADDR = 20
	RTM_DELADDR = 21
	RTM_GETADDR = 22
)

func (c *nlConn) flushAddrs(index int) error {
	// Dump all IPv4 addrs, then delete each one on our interface.
	body := encodeIfAddr(syscall.AF_INET, 0, index, nil, 0)
	type todo struct {
		index     int
		prefixLen int
		addr      net.IP
	}
	var pending []todo
	err := c.request(RTM_GETADDR, syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP, body, func(h *syscall.NlMsghdr, data []byte) error {
		if h.Type != RTM_NEWADDR {
			return nil
		}
		if len(data) < 8 {
			return nil
		}
		ifam := (*ifaddrmsg)(unsafe.Pointer(&data[0]))
		if int(ifam.Index) != index || ifam.Family != syscall.AF_INET {
			return nil
		}
		for _, attr := range parseRtAttrs(data[8:]) {
			if attr.typ == IFA_LOCAL || attr.typ == IFA_ADDRESS {
				if len(attr.data) == 4 {
					pending = append(pending, todo{index, int(ifam.Prefixlen), net.IP(append([]byte(nil), attr.data...))})
					return nil
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, t := range pending {
		body := encodeIfAddr(syscall.AF_INET, t.prefixLen, t.index, t.addr, 0)
		if err := c.request(RTM_DELADDR, syscall.NLM_F_REQUEST|syscall.NLM_F_ACK, body, nil); err != nil {
			// ENODEV / ENOENT races are benign — keep going.
			if errno, ok := err.(syscall.Errno); ok && (errno == syscall.ENOENT || errno == syscall.ENODEV) {
				continue
			}
			return err
		}
	}
	return nil
}

func (c *nlConn) addAddr(index int, ip net.IP, prefix int) error {
	body := encodeIfAddr(syscall.AF_INET, prefix, index, ip, 0)
	flags := uint16(syscall.NLM_F_REQUEST | syscall.NLM_F_ACK | syscall.NLM_F_CREATE | syscall.NLM_F_EXCL)
	return c.request(RTM_NEWADDR, flags, body, nil)
}

func encodeIfAddr(family uint8, prefix int, index int, addr net.IP, scope uint8) []byte {
	hdr := ifaddrmsg{
		Family:    family,
		Prefixlen: uint8(prefix),
		Scope:     scope,
		Index:     uint32(index),
	}
	buf := make([]byte, unsafe.Sizeof(hdr))
	*(*ifaddrmsg)(unsafe.Pointer(&buf[0])) = hdr
	if addr != nil {
		buf = appendRtAttr(buf, IFA_LOCAL, addr)
		buf = appendRtAttr(buf, IFA_ADDRESS, addr)
	}
	return buf
}

// ─── route ops ────────────────────────────────────────────────────────

// rtmsg per include/uapi/linux/rtnetlink.h
type rtmsg struct {
	Family   uint8
	DstLen   uint8
	SrcLen   uint8
	Tos      uint8
	Table    uint8
	Protocol uint8
	Scope    uint8
	Type     uint8
	Flags    uint32
}

const (
	RTM_NEWROUTE = 24
	RTM_DELROUTE = 25

	RTA_DST     = 1
	RTA_OIF     = 4
	RTA_GATEWAY = 5

	RT_TABLE_MAIN   = 254
	RT_SCOPE_UNIV   = 0
	RT_PROT_BOOT    = 3
	RT_TYPE_UNICAST = 1
)

func (c *nlConn) addDefaultRoute(gw net.IP, oif int) error {
	body := encodeRoute(gw, oif)
	flags := uint16(syscall.NLM_F_REQUEST | syscall.NLM_F_ACK | syscall.NLM_F_CREATE | syscall.NLM_F_REPLACE)
	return c.request(RTM_NEWROUTE, flags, body, nil)
}

func (c *nlConn) delDefaultRoute() error {
	body := encodeRoute(nil, 0)
	err := c.request(RTM_DELROUTE, syscall.NLM_F_REQUEST|syscall.NLM_F_ACK, body, nil)
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok && (errno == syscall.ESRCH || errno == syscall.ENOENT) {
			return nil // no default route to delete
		}
	}
	return err
}

func encodeRoute(gw net.IP, oif int) []byte {
	hdr := rtmsg{
		Family:   syscall.AF_INET,
		DstLen:   0,
		Table:    RT_TABLE_MAIN,
		Protocol: RT_PROT_BOOT,
		Scope:    RT_SCOPE_UNIV,
		Type:     RT_TYPE_UNICAST,
	}
	buf := make([]byte, unsafe.Sizeof(hdr))
	*(*rtmsg)(unsafe.Pointer(&buf[0])) = hdr
	if gw != nil {
		buf = appendRtAttr(buf, RTA_GATEWAY, gw)
	}
	if oif != 0 {
		var oifBuf [4]byte
		binary.LittleEndian.PutUint32(oifBuf[:], uint32(oif))
		buf = appendRtAttr(buf, RTA_OIF, oifBuf[:])
	}
	return buf
}

// ─── rtattr helpers ───────────────────────────────────────────────────

type rtAttr struct {
	typ  uint16
	data []byte
}

func appendRtAttr(buf []byte, typ uint16, data []byte) []byte {
	// rtattr is aligned to 4 bytes.
	const rtaHdr = 4
	total := rtaHdr + len(data)
	aligned := (total + 3) &^ 3
	tail := make([]byte, aligned)
	binary.LittleEndian.PutUint16(tail[0:2], uint16(total))
	binary.LittleEndian.PutUint16(tail[2:4], typ)
	copy(tail[4:], data)
	return append(buf, tail...)
}

// ─── link MAC ─────────────────────────────────────────────────────────

// ifinfomsg per include/uapi/linux/rtnetlink.h.
type ifinfomsg struct {
	Family uint8
	_      uint8
	Type   uint16
	Index  int32
	Flags  uint32
	Change uint32
}

const (
	RTM_NEWLINK  uint16 = 16
	IFLA_ADDRESS uint16 = 1
)

// netlinkSetMAC parses macStr (xx:xx:xx:xx:xx:xx) and sets it on ifName.
// Idempotent: no-op if current MAC already matches. Requires the iface to
// be administratively down briefly for the change — done inline via Flags.
func netlinkSetMAC(ifName, macStr string) error {
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		return fmt.Errorf("parse mac %q: %w", macStr, err)
	}
	if len(mac) != 6 {
		return fmt.Errorf("mac %q not 6 bytes", macStr)
	}
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return fmt.Errorf("%s: %w", ifName, err)
	}
	// Already the right MAC? Skip.
	curMAC := iface.HardwareAddr
	if len(curMAC) == 6 && curMAC[0] == mac[0] && curMAC[1] == mac[1] &&
		curMAC[2] == mac[2] && curMAC[3] == mac[3] && curMAC[4] == mac[4] && curMAC[5] == mac[5] {
		return nil
	}

	c, err := dialNetlink()
	if err != nil {
		return err
	}
	defer c.close()

	wasUp := iface.Flags&net.FlagUp != 0
	if wasUp {
		if err := c.setLinkFlags(iface.Index, 0, syscall.IFF_UP); err != nil {
			return fmt.Errorf("link down: %w", err)
		}
	}
	if err := c.setLinkMAC(iface.Index, mac); err != nil {
		// Try to restore UP state before returning
		if wasUp {
			_ = c.setLinkFlags(iface.Index, syscall.IFF_UP, syscall.IFF_UP)
		}
		return fmt.Errorf("set mac: %w", err)
	}
	if wasUp {
		if err := c.setLinkFlags(iface.Index, syscall.IFF_UP, syscall.IFF_UP); err != nil {
			return fmt.Errorf("link up: %w", err)
		}
	}
	return nil
}

func (c *nlConn) setLinkMAC(index int, mac net.HardwareAddr) error {
	hdr := ifinfomsg{Family: syscall.AF_UNSPEC, Index: int32(index)}
	buf := make([]byte, unsafe.Sizeof(hdr))
	*(*ifinfomsg)(unsafe.Pointer(&buf[0])) = hdr
	buf = appendRtAttr(buf, IFLA_ADDRESS, []byte(mac))
	flags := uint16(syscall.NLM_F_REQUEST | syscall.NLM_F_ACK)
	return c.request(RTM_NEWLINK, flags, buf, nil)
}

func (c *nlConn) setLinkFlags(index int, value, mask uint32) error {
	hdr := ifinfomsg{
		Family: syscall.AF_UNSPEC,
		Index:  int32(index),
		Flags:  value,
		Change: mask,
	}
	buf := make([]byte, unsafe.Sizeof(hdr))
	*(*ifinfomsg)(unsafe.Pointer(&buf[0])) = hdr
	flags := uint16(syscall.NLM_F_REQUEST | syscall.NLM_F_ACK)
	return c.request(RTM_NEWLINK, flags, buf, nil)
}

func parseRtAttrs(buf []byte) []rtAttr {
	var out []rtAttr
	for len(buf) >= 4 {
		length := binary.LittleEndian.Uint16(buf[0:2])
		if int(length) < 4 || int(length) > len(buf) {
			break
		}
		typ := binary.LittleEndian.Uint16(buf[2:4])
		out = append(out, rtAttr{typ: typ, data: buf[4:length]})
		// next aligned
		aligned := (int(length) + 3) &^ 3
		if aligned > len(buf) {
			break
		}
		buf = buf[aligned:]
	}
	return out
}
