package vm

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"unsafe"

	log "github.com/sirupsen/logrus"
)

// Firecracker UFFD protocol reference:
//   https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/handling-page-faults-on-snapshot-resume.md
//
// Firecracker connects to our unix socket during `PUT /snapshot/load`, sends
// ONE sendmsg() carrying:
//   - iovec: JSON array describing memory mappings (base virt addr, size,
//     offset-in-memfile, page size)
//   - ancillary: SCM_RIGHTS with the userfaultfd file descriptor
// We register those regions with the UFFD and then serve pagefault events by
// `UFFDIO_COPY`ing the right bytes from an mmap'd memfile into the guest.

// userfaultfd ioctl numbers on x86_64 / kernel 5+. These are fixed by the
// kernel ABI; no autoconf needed.
const (
	sysUserfaultfd    = 323
	uffdioAPI         = 0xC018AA3F
	uffdioRegister    = 0xC020AA00
	uffdioCopy        = 0xC028AA03
	uffdAPIVersion    = 0xAA
	uffdRegModeMiss   = 1
	uffdEventPagefaul = 0x12
)

type uffdMsg struct {
	Event     uint8
	Reserved1 uint8
	Reserved2 uint16
	Reserved3 uint32
	// union starts here; for PAGEFAULT:
	Flags   uint64
	Address uint64
	// Followed by more fields we don't care about.
	Feat uint32
	Pad  uint32
}

type uffdRegion struct {
	BaseHostVirtAddr uint64 `json:"base_host_virt_addr"`
	Size             uint64 `json:"size"`
	Offset           uint64 `json:"offset"`
	// Firecracker 1.15 sends `page_size` (bytes). Older versions used
	// `page_size_kib` and some still populate both (with bytes in *both*
	// fields — the name is a lie). We accept either and interpret the
	// value as bytes.
	PageSize    uint32 `json:"page_size"`
	PageSizeKib uint32 `json:"page_size_kib"`
}

func (r *uffdRegion) pageBytes() uint64 {
	if r.PageSize > 0 {
		return uint64(r.PageSize)
	}
	if r.PageSizeKib > 0 {
		return uint64(r.PageSizeKib)
	}
	return 4096 // sane default = 4 KiB
}

type uffdIOCopy struct {
	Dst, Src, Len, Mode uint64
	Copy                int64
}

// UFFDServer serves pagefaults for one VM's snapshot restore. Created before
// PUT /snapshot/load, lives for the VM's lifetime.
type UFFDServer struct {
	SockPath    string
	MemFilePath string

	ln       net.Listener
	stopOnce sync.Once
	done     chan struct{}
}

// StartUFFDServer opens a unix socket at sockPath and serves UFFD fault
// events from memFilePath when Firecracker connects. Returns immediately;
// the accept + fault-serving loop runs in goroutines until Close.
func StartUFFDServer(sockPath, memFilePath string) (*UFFDServer, error) {
	_ = os.Remove(sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("uffd: listen %s: %w", sockPath, err)
	}
	s := &UFFDServer{
		SockPath:    sockPath,
		MemFilePath: memFilePath,
		ln:          ln,
		done:        make(chan struct{}),
	}
	go s.acceptLoop()
	return s, nil
}

func (s *UFFDServer) Close() {
	s.stopOnce.Do(func() {
		close(s.done)
		_ = s.ln.Close()
		_ = os.Remove(s.SockPath)
	})
}

func (s *UFFDServer) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				log.Warnf("uffd: accept %s: %v", s.SockPath, err)
				return
			}
		}
		// Only one connection per VM (Firecracker connects exactly once).
		go s.serve(conn.(*net.UnixConn))
	}
}

func (s *UFFDServer) serve(c *net.UnixConn) {
	defer c.Close()

	// Read sendmsg: JSON body + SCM_RIGHTS with uffd fd.
	buf := make([]byte, 1<<15)
	oob := make([]byte, 1024)
	n, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
	if err != nil {
		log.Errorf("uffd: readmsg: %v", err)
		return
	}
	_ = oobn

	// Pull the uffd fd out of the ancillary data.
	uffdFd := -1
	if oobn > 0 {
		cmsgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			log.Errorf("uffd: parse cmsg: %v", err)
			return
		}
		for _, m := range cmsgs {
			if m.Header.Level == syscall.SOL_SOCKET && m.Header.Type == syscall.SCM_RIGHTS {
				fds, err := syscall.ParseUnixRights(&m)
				if err == nil && len(fds) > 0 {
					uffdFd = fds[0]
				}
			}
		}
	}
	if uffdFd < 0 {
		log.Errorf("uffd: no SCM_RIGHTS fd in firecracker handshake")
		return
	}
	defer syscall.Close(uffdFd)

	// Regions JSON.
	var regions []uffdRegion
	if err := json.Unmarshal(buf[:n], &regions); err != nil {
		log.Errorf("uffd: parse regions: %v (body: %q)", err, string(buf[:n]))
		return
	}
	if len(regions) == 0 {
		log.Errorf("uffd: no regions in handshake")
		return
	}

	// mmap the memfile so we can serve pages from it.
	f, err := os.Open(s.MemFilePath)
	if err != nil {
		log.Errorf("uffd: open memfile %s: %v", s.MemFilePath, err)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return
	}
	memMap, err := syscall.Mmap(int(f.Fd()), 0, int(st.Size()), syscall.PROT_READ, syscall.MAP_PRIVATE)
	if err != nil {
		log.Errorf("uffd: mmap memfile: %v", err)
		return
	}
	defer func() { _ = syscall.Munmap(memMap) }()

	// Firecracker does UFFDIO_API and UFFDIO_REGISTER on its side BEFORE
	// passing the fd to us — confirmed by firecracker's reference uffd
	// handler (it never calls REGISTER). We only serve pagefaults.

	// The UFFD fd arrives in non-blocking mode. Switch to blocking so our
	// read() sleeps until an event is ready (instead of burning CPU or
	// exiting on EAGAIN).
	if err := syscall.SetNonblock(uffdFd, false); err != nil {
		log.Warnf("uffd: SetNonblock: %v", err)
	}

	// Pagefault loop.
	var msg uffdMsg
	msgBuf := (*[unsafe.Sizeof(msg)]byte)(unsafe.Pointer(&msg))[:]
	faults := 0
	for {
		select {
		case <-s.done:
			return
		default:
		}
		nr, err := syscall.Read(uffdFd, msgBuf)
		if err != nil || nr == 0 {
			return
		}
		if msg.Event != uffdEventPagefaul {
			continue
		}
		addr := msg.Address
		// Find the region this fault belongs to.
		var reg *uffdRegion
		for i := range regions {
			r := &regions[i]
			if addr >= r.BaseHostVirtAddr && addr < r.BaseHostVirtAddr+r.Size {
				reg = r
				break
			}
		}
		if reg == nil {
			log.Warnf("uffd: fault addr %x not in any region", addr)
			continue
		}
		pageSize := reg.pageBytes()
		pageAddr := addr & ^(pageSize - 1)
		regionOff := pageAddr - reg.BaseHostVirtAddr
		fileOff := reg.Offset + regionOff
		if fileOff+pageSize > uint64(len(memMap)) {
			log.Warnf("uffd: fault off-of-memfile addr=%x fileOff=%d", addr, fileOff)
			continue
		}
		cp := uffdIOCopy{
			Dst: pageAddr,
			Src: uint64(uintptr(unsafe.Pointer(&memMap[fileOff]))),
			Len: pageSize,
		}
		if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(uffdFd), uintptr(uffdioCopy), uintptr(unsafe.Pointer(&cp))); e != 0 {
			// EAGAIN means the page is gone (VM killed); benign.
			if e != syscall.EAGAIN {
				log.Warnf("uffd: UFFDIO_COPY dst=%x: %v", pageAddr, e)
			}
		}
		faults++
	}
}
