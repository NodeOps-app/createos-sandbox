package process

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	processCgroupRoot          = "/sys/fs/cgroup/fc-agent-processes"
	processCgroupRemoveRetries = 20
	processCgroupRemoveBackoff = 5 * time.Millisecond
)

type processCgroup struct {
	path      string
	attachFD  *os.File
	closeOnce sync.Once
	removeMu  sync.Mutex
}

func createProcessCgroup(id processID) (*processCgroup, error) {
	if _, err := parseProcessID(string(id)); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(processCgroupRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create process cgroup root: %w", err)
	}
	path := filepath.Join(processCgroupRoot, string(id))
	if err := os.Mkdir(path, 0o700); err != nil {
		return nil, fmt.Errorf("create process cgroup: %w", err)
	}

	cleanup := func() { _ = os.Remove(path) }
	for _, name := range []string{"cgroup.events", "cgroup.kill", "cgroup.procs"} {
		if _, err := os.Stat(filepath.Join(path, name)); err != nil {
			cleanup()
			return nil, fmt.Errorf("process cgroup requires %s: %w", name, err)
		}
	}
	attachFD, err := os.Open(path)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("open process cgroup: %w", err)
	}
	return &processCgroup{path: path, attachFD: attachFD}, nil
}

func (c *processCgroup) fd() int {
	return int(c.attachFD.Fd())
}

func (c *processCgroup) closeAttachFD() {
	c.closeOnce.Do(func() {
		if c.attachFD != nil {
			_ = c.attachFD.Close()
		}
	})
}

func (c *processCgroup) kill() error {
	if err := os.WriteFile(filepath.Join(c.path, "cgroup.kill"), []byte("1"), 0); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("kill process cgroup: %w", err)
	}
	return nil
}

// signal addresses current members through pidfds, never a cached PGID. Open
// the pidfd before rechecking membership so PID reuse cannot redirect a signal
// to a different workload. Descendants in nested cgroups are included.
func (c *processCgroup) signal(signal syscall.Signal) error {
	return filepath.WalkDir(c.path, func(path string, entry os.DirEntry, err error) error {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if entry.IsDir() || entry.Name() != "cgroup.procs" {
			return nil
		}
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		for _, member := range strings.Fields(string(data)) {
			pid, err := strconv.Atoi(member)
			if err != nil || pid <= 0 {
				return fmt.Errorf("invalid cgroup pid %q", member)
			}
			if err := signalCgroupMember(path, pid, signal); err != nil {
				return err
			}
		}
		return nil
	})
}

func signalCgroupMember(procsPath string, pid int, signal syscall.Signal) error {
	// pidfd syscalls have the same numbers on the Linux architectures we ship.
	const sysPidfdOpen = 434
	const sysPidfdSendSignal = 424
	fd, _, errno := syscall.Syscall(sysPidfdOpen, uintptr(pid), 0, 0)
	if errno == syscall.ESRCH {
		return nil
	}
	if errno != 0 {
		return fmt.Errorf("open process pidfd: %w", errno)
	}
	defer syscall.Close(int(fd))
	data, err := os.ReadFile(procsPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, member := range strings.Fields(string(data)) {
		if member != strconv.Itoa(pid) {
			continue
		}
		_, _, errno = syscall.Syscall6(sysPidfdSendSignal, fd, uintptr(signal), 0, 0, 0, 0)
		if errno != 0 && errno != syscall.ESRCH {
			return fmt.Errorf("signal cgroup member: %w", errno)
		}
		return nil
	}
	return nil
}

func (c *processCgroup) populated() (bool, error) {
	data, err := os.ReadFile(filepath.Join(c.path, "cgroup.events"))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("read process cgroup events: %w", err)
	}
	return parseCgroupPopulated(data)
}

func parseCgroupPopulated(data []byte) (bool, error) {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "populated" {
			switch fields[1] {
			case "0":
				return false, nil
			case "1":
				return true, nil
			default:
				return false, errors.New("invalid process cgroup populated value")
			}
		}
	}
	return false, errors.New("process cgroup events missing populated field")
}

func (c *processCgroup) waitEmptyFor(ctx context.Context, grace time.Duration) (bool, error) {
	return c.waitUntilEmpty(ctx, time.Now().Add(grace), true)
}

func (c *processCgroup) waitEmpty(ctx context.Context) error {
	_, err := c.waitUntilEmpty(ctx, time.Time{}, false)
	return err
}

// waitUntilEmpty uses the poll notification provided by cgroup.events. The
// cancellation pipe makes context cancellation wake the same epoll wait, so no
// periodic timer or cgroup-file reads are needed.
func (c *processCgroup) waitUntilEmpty(
	ctx context.Context,
	deadline time.Time,
	hasDeadline bool,
) (bool, error) {
	// Observers must not hold removeMu while waiting: DELETE needs to wait
	// concurrently before escalating to cgroup.kill. An unlinked cgroup.events
	// can return ENXIO or ENODEV; removal is only allowed after the tree
	// becomes empty.
	if err := ctx.Err(); err != nil {
		return false, err
	}

	eventsFile, err := os.Open(filepath.Join(c.path, "cgroup.events"))
	if err != nil {
		if os.IsNotExist(err) {
			return true, nil
		}
		return false, fmt.Errorf("open process cgroup events: %w", err)
	}
	defer eventsFile.Close()

	epollFD, err := syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)
	if err != nil {
		return false, fmt.Errorf("create process cgroup epoll: %w", err)
	}
	defer syscall.Close(epollFD)
	if err := syscall.EpollCtl(epollFD, syscall.EPOLL_CTL_ADD, int(eventsFile.Fd()), &syscall.EpollEvent{
		Events: syscall.EPOLLPRI | syscall.EPOLLERR,
		Fd:     int32(eventsFile.Fd()),
	}); err != nil {
		if _, statErr := os.Stat(c.path); os.IsNotExist(statErr) {
			return true, nil
		}
		return false, fmt.Errorf("watch process cgroup events: %w", err)
	}

	cancelRead, cancelWrite, err := os.Pipe()
	if err != nil {
		return false, fmt.Errorf("create process cgroup cancellation pipe: %w", err)
	}
	stopCancel := make(chan struct{})
	cancelDone := make(chan struct{})
	go func() {
		defer close(cancelDone)
		select {
		case <-ctx.Done():
			_, _ = cancelWrite.Write([]byte{1})
		case <-stopCancel:
		}
	}()
	defer func() {
		close(stopCancel)
		<-cancelDone
		_ = cancelRead.Close()
		_ = cancelWrite.Close()
	}()
	if err := syscall.EpollCtl(epollFD, syscall.EPOLL_CTL_ADD, int(cancelRead.Fd()), &syscall.EpollEvent{
		Events: syscall.EPOLLIN,
		Fd:     int32(cancelRead.Fd()),
	}); err != nil {
		return false, fmt.Errorf("watch process cgroup cancellation: %w", err)
	}

	readPopulated := func() (bool, error) {
		if _, err := eventsFile.Seek(0, 0); err != nil {
			if errors.Is(err, syscall.ENXIO) || errors.Is(err, syscall.ENODEV) {
				return false, nil // the empty cgroup was removed
			}
			return false, err
		}
		buffer := make([]byte, 256)
		n, err := eventsFile.Read(buffer)
		if err != nil {
			if errors.Is(err, syscall.ENXIO) || errors.Is(err, syscall.ENODEV) {
				return false, nil // the empty cgroup was removed
			}
			return false, err
		}
		return parseCgroupPopulated(buffer[:n])
	}
	if populated, err := readPopulated(); err != nil || !populated {
		return !populated, err
	}

	wakeups := make([]syscall.EpollEvent, 2)
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		timeout := -1
		if hasDeadline {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return false, nil
			}
			timeout = int((remaining + time.Millisecond - 1) / time.Millisecond)
		}
		n, err := syscall.EpollWait(epollFD, wakeups, timeout)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("wait for process cgroup event: %w", err)
		}
		if n == 0 {
			return false, nil
		}
		for _, event := range wakeups[:n] {
			if event.Fd == int32(cancelRead.Fd()) {
				return false, ctx.Err()
			}
		}
		if populated, err := readPopulated(); err != nil || !populated {
			return !populated, err
		}
	}
}

func (c *processCgroup) removeIfEmpty() error {
	populated, err := c.populated()
	if err != nil || populated {
		return err
	}
	return c.remove()
}

func (c *processCgroup) remove() error {
	// The command reaper and an explicit DELETE can observe the cgroup become
	// empty at the same time. Serialize removal so cgroupfs never sees two
	// concurrent rmdir operations (one can otherwise return EBUSY even though
	// the other succeeds). A later retry remains idempotent via IsNotExist.
	c.removeMu.Lock()
	defer c.removeMu.Unlock()
	c.closeAttachFD()
	for attempt := 0; attempt < processCgroupRemoveRetries; attempt++ {
		err := os.Remove(c.path)
		if err == nil || os.IsNotExist(err) {
			return nil
		}
		// cgroupfs may report EBUSY briefly after cgroup.events first reports
		// populated=0 while the kernel finishes releasing the final task. Keep
		// DELETE deterministic instead of requiring a client-side retry.
		if !errors.Is(err, syscall.EBUSY) || attempt == processCgroupRemoveRetries-1 {
			return fmt.Errorf("remove process cgroup: %w", err)
		}
		time.Sleep(processCgroupRemoveBackoff)
	}
	return nil
}
