#!/usr/bin/env python3
"""Record file-cache ranges for an image runtime during image preparation.

Run in an isolated image build or disposable VM, never on a serving host:
  python3 warmup.py --output /etc/createos/warmup.json /usr/local/bin/node --version
The command is run only here, not by the boot-time agent. Regenerate after
changing the runtime or libraries. At most five files and 32 MiB are recorded.
"""
import argparse
import ctypes
import json
import mmap
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile


def resident_ranges(fd, size):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                          ctypes.c_int, ctypes.c_int, ctypes.c_long]
    libc.mmap.restype = ctypes.c_void_p
    libc.mincore.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    address = libc.mmap(None, size, 0, mmap.MAP_PRIVATE, fd, 0)
    if address == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_errno(), "mmap")
    try:
        pages = (size + 4095) // 4096
        vector = (ctypes.c_ubyte * pages)()
        if libc.mincore(address, size, vector):
            raise OSError(ctypes.get_errno(), "mincore")
        ranges = []
        start = None
        for i in range(pages + 1):
            present = i < pages and vector[i] & 1
            if present and start is None:
                start = i
            elif not present and start is not None:
                offset = start * 4096
                ranges.append({"offset": offset, "length": min(size, i * 4096) - offset})
                start = None
        return ranges
    finally:
        libc.munmap(address, size)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not args.command or not os.path.isabs(args.command[0]):
        parser.error("provide an absolute executable path and its arguments")
    if os.sysconf("SC_PAGE_SIZE") != 4096:
        parser.error("this image profile requires 4 KiB pages")
    executable = str(Path(args.command[0]).resolve(strict=True))
    dependencies = subprocess.run(["ldd", executable], capture_output=True, text=True, timeout=10)
    paths = {executable}
    paths.update(str(Path(p).resolve(strict=True)) for p in
                 re.findall(r"(/[^\s()]+)", dependencies.stdout))
    handles = []
    try:
        for path in sorted(paths):
            fd = os.open(path, os.O_RDONLY)
            handles.append((path, fd))
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= 512 << 20:
                raise ValueError("profile input must be a bounded regular file")
            # Per-file eviction, never global drop_caches. Some shared library
            # pages may stay mapped by the profiler; including them is safe.
            os.fsync(fd)
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        subprocess.run(args.command, check=True, timeout=10, stdout=subprocess.DEVNULL)
        files = [{"path": path, "ranges": resident_ranges(fd, os.fstat(fd).st_size)}
                 for path, fd in handles]
        files = [f for f in files if f["ranges"]]
        files.sort(key=lambda f: sum(r["length"] for r in f["ranges"]), reverse=True)
        files = files[:5]
        total = sum((r["length"] + 4095) // 4096 * 4096 for f in files for r in f["ranges"])
        count = sum(len(f["ranges"]) for f in files)
        if not files or total > 32 << 20 or count > 256:
            raise ValueError("profile exceeds warmup limits; regenerate in an idle disposable image")
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", dir=output.parent, delete=False) as tmp:
            temporary = tmp.name
            json.dump({"files": files}, tmp, separators=(",", ":"))
            tmp.write("\n")
        try:
            os.chmod(temporary, 0o644)
            os.replace(temporary, output)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        print(f"warmup: {len(files)} files, {count} ranges, {total} bytes")
    finally:
        for _, fd in handles:
            os.close(fd)


if __name__ == "__main__":
    main()
