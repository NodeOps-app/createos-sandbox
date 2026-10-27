package childreaper

import (
	"errors"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// Agent PID 1 must reap orphaned descendants, but its wildcard Wait4 can win
// the race against an exec.Cmd waiting for a direct child. Preserve every
// stolen status briefly so the child's owner can recover the real exit facts.
var reaped sync.Map // int (pid) -> syscall.WaitStatus

func Run() {
	ch := make(chan os.Signal, 16)
	signal.Notify(ch, syscall.SIGCHLD)
	drain()
	for range ch {
		drain()
	}
}

func drain() {
	for {
		var status syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
		if err != nil || pid <= 0 {
			return
		}
		reaped.Store(pid, status)
		capturedPID := pid
		time.AfterFunc(30*time.Second, func() { reaped.Delete(capturedPID) })
	}
}

// TakeStatus returns a status captured by the PID 1 wildcard reaper when the
// caller's own wait lost with ECHILD. SIGCHLD delivery and map publication are
// asynchronous, so allow a short handoff window.
func TakeStatus(waitErr error, pid int) (syscall.WaitStatus, bool) {
	if !errors.Is(waitErr, syscall.ECHILD) || pid <= 0 {
		return 0, false
	}
	deadline := time.Now().Add(50 * time.Millisecond)
	for {
		if value, ok := reaped.LoadAndDelete(pid); ok {
			return value.(syscall.WaitStatus), true
		}
		if time.Now().After(deadline) {
			return 0, false
		}
		time.Sleep(200 * time.Microsecond)
	}
}

func Forget(pid int) {
	if pid > 0 {
		reaped.Delete(pid)
	}
}
