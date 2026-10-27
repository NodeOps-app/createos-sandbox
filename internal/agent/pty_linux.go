package agent

// Pseudo-terminal allocation.
//
// Adapted from github.com/creack/pty (MIT License, Copyright (c) 2011
// Keith Rarick). Trimmed to the Linux-only path and inlined as a source
// file so fc-agent keeps its zero-non-stdlib-dependency guarantee — see
// `make check-agent`.

import (
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

// Linux ioctl numbers for the /dev/ptmx pty pair. Defined locally so we
// don't depend on whether the stdlib's syscall package happens to export
// them on the build platform.
const (
	ioctlGetPtyNum = 0x80045430 // TIOCGPTN  — read the slave's number
	ioctlSetPtyLck = 0x40045431 // TIOCSPTLCK — lock/unlock the slave
)

// openPTY allocates a new pseudo-terminal pair. It returns the master
// ("ptmx") side, which the agent holds and reads/writes as the
// keyboard+screen, and the slave ("/dev/pts/N") side, which becomes the
// shell's controlling terminal.
func openPTY() (master, slave *os.File, err error) {
	master, err = os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			_ = master.Close()
		}
	}()

	// Unlock the slave so it can be opened.
	var unlock int32
	if err = ioctl(master.Fd(), ioctlSetPtyLck, uintptr(unsafe.Pointer(&unlock))); err != nil {
		return nil, nil, err
	}

	// Resolve the slave device path: /dev/pts/<n>.
	var ptn uint32
	if err = ioctl(master.Fd(), ioctlGetPtyNum, uintptr(unsafe.Pointer(&ptn))); err != nil {
		return nil, nil, err
	}
	slave, err = os.OpenFile("/dev/pts/"+strconv.Itoa(int(ptn)), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	return master, slave, nil
}

// winsize mirrors `struct winsize` from <termios.h>.
type winsize struct {
	rows uint16
	cols uint16
	x    uint16
	y    uint16
}

// setWinsize sets the terminal dimensions on a pty fd.
func setWinsize(f *os.File, rows, cols uint16) error {
	ws := winsize{rows: rows, cols: cols}
	return ioctl(f.Fd(), syscall.TIOCSWINSZ, uintptr(unsafe.Pointer(&ws)))
}

func ioctl(fd, cmd, ptr uintptr) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, cmd, ptr); e != 0 {
		return e
	}
	return nil
}
