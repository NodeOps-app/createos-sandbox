package process

// Linux-only pseudo-terminal allocation kept in the guest process package so
// the new persistent PTY API does not depend on or modify the legacy /shell
// implementation in the parent agent package.

import (
	"bytes"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

const (
	ioctlGetPtyNum = 0x80045430 // TIOCGPTN
	ioctlSetPtyLck = 0x40045431 // TIOCSPTLCK
)

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

	var unlock int32
	if err = ioctl(master.Fd(), ioctlSetPtyLck, uintptr(unsafe.Pointer(&unlock))); err != nil {
		return nil, nil, err
	}
	var ptyNumber uint32
	if err = ioctl(master.Fd(), ioctlGetPtyNum, uintptr(unsafe.Pointer(&ptyNumber))); err != nil {
		return nil, nil, err
	}
	slave, err = os.OpenFile(
		"/dev/pts/"+strconv.Itoa(int(ptyNumber)),
		os.O_RDWR|syscall.O_NOCTTY,
		0,
	)
	if err != nil {
		return nil, nil, err
	}
	return master, slave, nil
}

type winsize struct {
	rows uint16
	cols uint16
	x    uint16
	y    uint16
}

func setWinsize(file *os.File, rows, cols uint16) error {
	size := winsize{rows: rows, cols: cols}
	return ioctl(file.Fd(), syscall.TIOCSWINSZ, uintptr(unsafe.Pointer(&size)))
}

func foregroundProcessGroup(file *os.File) (int, error) {
	var pgid int32
	if err := ioctl(file.Fd(), syscall.TIOCGPGRP, uintptr(unsafe.Pointer(&pgid))); err != nil {
		return 0, err
	}
	if pgid <= 0 {
		return 0, syscall.ESRCH
	}
	return int(pgid), nil
}

func (r *processRecord) foregroundProcess() *ForegroundProcess {
	r.mu.RLock()
	master := r.pty
	state := r.state
	r.mu.RUnlock()
	if master == nil || state.ended() {
		return nil
	}

	pgid, err := foregroundProcessGroup(master)
	if err != nil {
		return nil
	}
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pgid) + "/cmdline")
	if err != nil {
		return nil
	}
	data = bytes.TrimRight(data, "\x00")
	if len(data) == 0 {
		return nil
	}
	parts := bytes.Split(data, []byte{0})
	argv := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) > 0 {
			argv = append(argv, string(part))
		}
	}
	if len(argv) == 0 {
		return nil
	}
	return &ForegroundProcess{
		PID:  pgid,
		Cmd:  argv[0],
		Args: append([]string(nil), argv[1:]...),
	}
}

func ioctl(fd, command, pointer uintptr) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, command, pointer); errno != 0 {
		return errno
	}
	return nil
}
