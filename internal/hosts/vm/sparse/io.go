package sparse

import (
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// Sparse-aware I/O helpers for the pause/resume hot path.
//
// Why this exists: a per-VM ext4 overlay is sized at create time
// (default 10 GiB) and is sparse on disk — the kernel only allocates
// blocks for actually-written regions. A sandbox that just touches
// /tmp/marker has ~50 KB of real data inside a 10 GB sparse file.
//
// The naive io.Copy(zstd, file) reads the entire 10 GB as zero bytes
// for the hole regions (the kernel synthesizes them on read), which
// is ~17s of pure read I/O on commodity SSDs even though the bytes
// will compress to almost nothing. Same problem in reverse on
// decompress: io.Copy(file, zstd) writes 10 GB of literal zeros,
// turning a sparse file into a non-sparse one and burning ~20s of
// disk write.
//
// Reader uses lseek(SEEK_HOLE)/lseek(SEEK_DATA) to identify
// hole regions and feed pre-allocated zero buffers to the consumer
// without touching disk. Copy detects zero blocks in the
// decompressed stream and uses Seek to advance the destination
// instead of Write, preserving sparseness.
//
// Net effect on a 10 GB overlay with ~50 KB live data:
//   compress: ~17s → ~50 ms (only the live data is read from disk)
//   decompress: ~20s → ~100 ms (only the live data is written)

// SEEK_HOLE / SEEK_DATA are defined in unistd.h on Linux but not
// surfaced by package syscall on all toolchains; redeclare here.
const (
	seekData = 3
	seekHole = 4
)

// Reader streams a file's contents as if it were a normal
// io.Reader, but for hole regions it returns buffered zero bytes
// without issuing a disk read. The output byte sequence is identical
// to what plain io.Copy would produce, so any consumer (e.g. zstd
// encoder) sees the same data.
//
// Region boundaries are computed once via SEEK_HOLE/SEEK_DATA and
// cached, so successive Read calls inside the same data or hole
// region don't pay per-read syscall cost. zstd typically pulls 128
// KiB at a time; without the cache a 256 MiB non-sparse memfile would
// trigger ~4000 lseek calls. With the cache it's one per region — for
// a fully-non-sparse file that's one Seek for the whole transfer.
type Reader struct {
	f     *os.File
	fd    int
	size  int64
	pos   int64
	zeros []byte // grows on demand; holds pre-zeroed bytes for hole fills

	// Cached current region. Valid when regionKnown=true and
	// regionStart ≤ pos < regionEnd.
	regionStart  int64
	regionEnd    int64
	regionIsData bool
	regionKnown  bool
}

func NewReader(f *os.File) (*Reader, error) {
	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	return &Reader{
		f:    f,
		fd:   int(f.Fd()),
		size: stat.Size(),
	}, nil
}

// resolveRegion populates the regionStart/End/IsData cache for the
// region containing pos. Two lseek syscalls in the worst case (one
// SEEK_DATA, one SEEK_HOLE), only invoked when the cache is stale.
func (s *Reader) resolveRegion() error {
	dataAt, err := unix.Seek(s.fd, s.pos, seekData)
	if err == syscall.ENXIO {
		// No more data — rest of file is hole.
		s.regionStart = s.pos
		s.regionEnd = s.size
		s.regionIsData = false
		s.regionKnown = true
		return nil
	} else if err != nil {
		return err
	}
	if dataAt > s.pos {
		// In a hole — extends from pos to dataAt.
		s.regionStart = s.pos
		s.regionEnd = dataAt
		s.regionIsData = false
		s.regionKnown = true
		return nil
	}
	// In a data region — extends from pos to next hole (or EOF).
	holeAt, err := unix.Seek(s.fd, s.pos, seekHole)
	if err != nil {
		holeAt = s.size
	}
	s.regionStart = s.pos
	s.regionEnd = holeAt
	s.regionIsData = true
	s.regionKnown = true
	return nil
}

func (s *Reader) Read(p []byte) (int, error) {
	if s.pos >= s.size {
		return 0, io.EOF
	}
	if !s.regionKnown || s.pos >= s.regionEnd {
		if err := s.resolveRegion(); err != nil {
			return 0, err
		}
	}

	// How much of the current region can we serve into p?
	remaining := s.regionEnd - s.pos
	toServe := int64(len(p))
	if toServe > remaining {
		toServe = remaining
	}

	if !s.regionIsData {
		// Hole: fill p with zeros from a pre-allocated zero buffer.
		if int64(cap(s.zeros)) < toServe {
			s.zeros = make([]byte, toServe)
		}
		copy(p[:toServe], s.zeros[:toServe])
		s.pos += toServe
		return int(toServe), nil
	}

	// Data: ReadAt from the current pos.
	n, err := s.f.ReadAt(p[:toServe], s.pos)
	s.pos += int64(n)
	if err == io.EOF && s.pos < s.size {
		return n, nil
	}
	return n, err
}

// Copy is the write-side analogue of Reader. It copies
// from src to dst (which must be a regular file we can Seek + Truncate)
// and detects all-zero blocks in the source stream, advancing dst's
// file position via Seek instead of writing zero bytes. This preserves
// sparseness on the destination — a file that decompresses to "10 GB
// of mostly zeros" lands on disk with only its non-zero blocks
// allocated.
//
// blockSize controls the zero-detection granularity. 64 KiB is a
// reasonable default — small enough to catch typical hole boundaries
// (filesystem block size is usually 4 KiB) but large enough that the
// per-block Seek vs Write decision is cheap relative to the work
// done by the compressor on the read side.
//
// On EOF, dst is Truncate'd to the total bytes consumed so its size
// reflects any trailing zero blocks that were Seek'd over (Seek
// doesn't extend file size; only Write does).
func Copy(dst *os.File, src io.Reader) (int64, error) {
	const blockSize = 64 * 1024
	buf := make([]byte, blockSize)
	var total int64
	for {
		n, rerr := io.ReadFull(src, buf)
		chunk := buf[:n]
		if n > 0 {
			if isAllZero(chunk) {
				if _, err := dst.Seek(int64(n), io.SeekCurrent); err != nil {
					return total, err
				}
			} else {
				if _, err := dst.Write(chunk); err != nil {
					return total, err
				}
			}
			total += int64(n)
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			if err := dst.Truncate(total); err != nil {
				return total, err
			}
			return total, nil
		}
		if rerr != nil {
			return total, rerr
		}
	}
}

// isAllZero is a tight loop the compiler can vectorize. For 64 KiB
// blocks the cost is microseconds even on modest hardware.
func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
