package sparse

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// sparse-archive format for ext4 overlay files.
//
// A 10 GiB ext4 overlay where the guest only wrote /tmp/marker is
// 99.96% filesystem-holes — ~4 MiB of real data. zstd compresses the
// hole-bytes well (50:1) but still has to *receive* every byte, so a
// 10 GiB stream takes ~10 s on a single core. That dominates pause
// wall time.
//
// This format walks data regions via SEEK_DATA/SEEK_HOLE and emits
// only [offset, length, bytes] tuples. For the typical sandbox the
// archive size ~= live data size, and compress wall ~= reading the
// live data (~50 ms on SSD). On decompress the destination is
// truncated to the original apparent size and each region is pwrite'd
// at its offset, which keeps the destination file sparse.
//
// Layout:
//   magic:    8 bytes ASCII "FCSPARSE"
//   version:  4 bytes uint32 LE
//   reserved: 4 bytes uint32 LE (= 0)
//   size:     8 bytes uint64 LE (apparent file size)
//   regions:  8 bytes uint64 LE (number of regions to follow)
//   for each region:
//     offset: 8 bytes uint64 LE
//     length: 8 bytes uint64 LE
//     bytes:  length bytes
//
// The archive is *not* re-compressed with zstd. Live overlay data is
// already small; another compression pass adds CPU and saves at most
// ~30% on the wire.

const (
	sparseArchiveMagic   = "FCSPARSE"
	sparseArchiveVersion = uint32(1)
	sparseHeaderBytes    = 32 // magic(8) + version(4) + reserved(4) + size(8) + regions(8)
)

// WriteArchive walks src as a sparse file and writes a
// sparse-archive of its data regions to dst. Returns the apparent
// (logical) source size, the number of bytes written to dst, and a
// hex sha256 of the archive bytes (computed during write so callers
// don't have to re-read the dst).
func WriteArchive(srcPath, dstPath string) (apparent int64, written int64, sha256Hex string, err error) {
	src, err := os.Open(srcPath)
	if err != nil {
		return 0, 0, "", err
	}
	defer src.Close()
	st, err := src.Stat()
	if err != nil {
		return 0, 0, "", err
	}
	apparent = st.Size()

	dst, err := os.CreateTemp(filepath.Dir(dstPath), ".overlay-archive-*")
	if err != nil {
		return 0, 0, "", err
	}
	defer os.Remove(dst.Name())
	hasher := sha256.New()
	mw := io.MultiWriter(dst, hasher)

	// Reserve space for the header; we'll come back and overwrite once
	// we know the region count.
	if _, err := dst.Write(make([]byte, sparseHeaderBytes)); err != nil {
		dst.Close()
		return 0, 0, "", err
	}
	// We can't tee the placeholder header into the hasher and then
	// rewrite it — sha256 is one-shot. Easiest: hash everything in a
	// final read pass at the end. But that's an extra disk read.
	// Alternative: build the header bytes in-memory, write data to
	// dst, then construct (header || data) hash by feeding header
	// through hasher first and then the data stream as we write it.
	// We do the latter: skip hashing the placeholder, hash header
	// after counting regions, then hash data as it's written. We use
	// two writers: one to dst, one to a buffer for the data section
	// so we can hash header-then-data.
	//
	// Simpler still: run sha256sum once at the end. Disk read of an
	// archive that's ~4 MiB is microseconds — irrelevant.
	_ = mw // unused; we'll re-hash at the end below

	src2 := src // keep alias; we Seek on src
	regionCount, dataBytes, err := iterateSparseRegions(src2, dst, apparent)
	if err != nil {
		dst.Close()
		return 0, 0, "", err
	}

	// Now write the header at offset 0.
	hdr := make([]byte, sparseHeaderBytes)
	copy(hdr[0:8], sparseArchiveMagic)
	binary.LittleEndian.PutUint32(hdr[8:12], sparseArchiveVersion)
	// hdr[12:16] reserved, zero
	binary.LittleEndian.PutUint64(hdr[16:24], uint64(apparent))
	binary.LittleEndian.PutUint64(hdr[24:32], uint64(regionCount))
	if _, err := dst.WriteAt(hdr, 0); err != nil {
		dst.Close()
		return 0, 0, "", err
	}
	if err := dst.Sync(); err != nil {
		dst.Close()
		return 0, 0, "", err
	}
	dstSize, err := dst.Seek(0, io.SeekEnd)
	if err != nil {
		dst.Close()
		return 0, 0, "", err
	}
	if err := dst.Close(); err != nil {
		return 0, 0, "", err
	}

	// Compute sha256 in one pass over the finished archive.
	rd, err := os.Open(dst.Name())
	if err != nil {
		return 0, 0, "", err
	}
	defer rd.Close()
	if _, err := io.Copy(hasher, rd); err != nil {
		return 0, 0, "", err
	}
	_ = dataBytes
	if err := os.Rename(dst.Name(), dstPath); err != nil {
		return 0, 0, "", err
	}
	return apparent, dstSize, hex.EncodeToString(hasher.Sum(nil)), nil
}

// iterateSparseRegions walks src via SEEK_DATA/SEEK_HOLE and writes
// [offset(8) | length(8) | bytes(length)] tuples for each data region
// into dst (sequentially after dst's current position). Returns the
// number of regions written and the total data bytes copied.
func iterateSparseRegions(src *os.File, dst *os.File, size int64) (int64, int64, error) {
	fd := int(src.Fd())
	var regions int64
	var dataBytes int64
	pos := int64(0)
	buf := make([]byte, 1<<20) // 1 MiB I/O buffer
	tupleHdr := make([]byte, 16)

	for pos < size {
		dataAt, err := unix.Seek(fd, pos, seekData)
		if err == syscall.ENXIO {
			break
		}
		if err != nil {
			return 0, 0, fmt.Errorf("SEEK_DATA at %d: %w", pos, err)
		}
		if dataAt >= size {
			break
		}
		holeAt, err := unix.Seek(fd, dataAt, seekHole)
		if err != nil {
			holeAt = size
		}
		regionLen := holeAt - dataAt

		binary.LittleEndian.PutUint64(tupleHdr[0:8], uint64(dataAt))
		binary.LittleEndian.PutUint64(tupleHdr[8:16], uint64(regionLen))
		if _, err := dst.Write(tupleHdr); err != nil {
			return 0, 0, fmt.Errorf("write tuple hdr: %w", err)
		}

		remaining := regionLen
		offset := dataAt
		for remaining > 0 {
			n := int64(len(buf))
			if n > remaining {
				n = remaining
			}
			r, err := src.ReadAt(buf[:n], offset)
			if err != nil && err != io.EOF {
				return 0, 0, fmt.Errorf("read at %d: %w", offset, err)
			}
			if r == 0 {
				break
			}
			if _, werr := dst.Write(buf[:r]); werr != nil {
				return 0, 0, fmt.Errorf("write data: %w", werr)
			}
			offset += int64(r)
			remaining -= int64(r)
			dataBytes += int64(r)
		}

		regions++
		pos = holeAt
	}
	return regions, dataBytes, nil
}

// ReadArchive expands an archive file at srcPath into dstPath as
// a sparse file. Truncates dst to the apparent size recorded in the
// archive, then pwrites each region at its offset. Hole regions remain
// unallocated.
func ReadArchive(srcPath, dstPath string) error {
	return readArchive(srcPath, dstPath)
}

// ValidateArchive checks completeness without materializing another disk image.
func ValidateArchive(srcPath string) error {
	return readArchive(srcPath, "")
}

func readArchive(srcPath, dstPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	hdr := make([]byte, sparseHeaderBytes)
	if _, err := io.ReadFull(src, hdr); err != nil {
		return fmt.Errorf("read header: %w", err)
	}
	if string(hdr[0:8]) != sparseArchiveMagic {
		return fmt.Errorf("not a sparse archive (bad magic)")
	}
	ver := binary.LittleEndian.Uint32(hdr[8:12])
	if ver != sparseArchiveVersion {
		return fmt.Errorf("sparse archive version %d unsupported", ver)
	}
	apparent := int64(binary.LittleEndian.Uint64(hdr[16:24]))
	regions := int64(binary.LittleEndian.Uint64(hdr[24:32]))

	if apparent < 0 || regions < 0 {
		return fmt.Errorf("invalid sparse archive size or region count")
	}
	var dst *os.File
	if dstPath != "" {
		dst, err = os.Create(dstPath)
		if err != nil {
			return err
		}
		defer dst.Close()
		if err := dst.Truncate(apparent); err != nil {
			return fmt.Errorf("truncate dst to %d: %w", apparent, err)
		}
	}

	tupleHdr := make([]byte, 16)
	buf := make([]byte, 1<<20)
	for i := int64(0); i < regions; i++ {
		if _, err := io.ReadFull(src, tupleHdr); err != nil {
			return fmt.Errorf("read region %d header: %w", i, err)
		}
		offset := int64(binary.LittleEndian.Uint64(tupleHdr[0:8]))
		length := int64(binary.LittleEndian.Uint64(tupleHdr[8:16]))
		if offset < 0 || length < 0 || offset > apparent || length > apparent-offset {
			return fmt.Errorf("region %d (%d+%d) exceeds apparent size %d", i, offset, length, apparent)
		}
		remaining := length
		writeAt := offset
		for remaining > 0 {
			n := int64(len(buf))
			if n > remaining {
				n = remaining
			}
			if _, err := io.ReadFull(src, buf[:n]); err != nil {
				return fmt.Errorf("read region %d data: %w", i, err)
			}
			if dst != nil {
				if _, err := dst.WriteAt(buf[:n], writeAt); err != nil {
					return fmt.Errorf("write region %d at %d: %w", i, writeAt, err)
				}
			}
			writeAt += n
			remaining -= n
		}
	}
	if n, err := src.Read(buf[:1]); n != 0 || err != io.EOF {
		return fmt.Errorf("unexpected sparse archive trailing data or read error: %v", err)
	}
	if dst != nil {
		return dst.Sync()
	}
	return nil
}
