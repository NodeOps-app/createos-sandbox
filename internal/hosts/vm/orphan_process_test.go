package vm

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Disposable processes only; no real VM, slot, file or network resources.
func TestOrphanProcessHelper(t *testing.T) {
	if len(flag.Args()) == 0 {
		t.Skip("subprocess helper")
	}
	if err := os.WriteFile(fmt.Sprintf("/proc/self/task/%d/comm", os.Getpid()), []byte("firecracker"), 0600); err != nil {
		t.Fatal(err)
	}
	if flag.Args()[len(flag.Args())-1] != "sb-graceful" {
		signal.Ignore(os.Interrupt)
	}
	fmt.Println("ready")
	for {
		time.Sleep(time.Hour)
	}
}

func auditFirecrackerProcess(t *testing.T, id string) (*exec.Cmd, <-chan error) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"-test.run=^TestOrphanProcessHelper$", "--"}
	if id != "" {
		args = append(args, "--id", id)
	} else {
		args = append(args, "--no-api")
	}
	cmd := exec.Command(exe, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait(); close(done) }()
	t.Cleanup(func() { _ = cmd.Process.Kill(); <-done })
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); ready <- line }()
	select {
	case line := <-ready:
		if line != "ready\n" {
			t.Fatalf("helper not ready: %q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("helper timeout")
	}
	return cmd, done
}

func TestOrphanCleanupProcessIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, id, expected string
		wantExit           bool
	}{
		{"reused PID", "sb-new", "sb-old", false},
		{"prefix is not identity", "sb-old-extra", "sb-old", false},
		{"graceful stop", "sb-graceful", "sb-graceful", true},
		{"missing identity", "", "sb-old", false},
		{"empty expected ID", "sb-new", "", false},
		{"matching identity", "sb-old", "sb-old", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cmd, done := auditFirecrackerProcess(t, tc.id)
			if !pidIsFirecracker(cmd.Process.Pid) {
				t.Fatal("helper does not have Firecracker comm")
			}
			CleanupVMArtifacts(OrphanCleanupSpec{ID: tc.expected, FCPid: cmd.Process.Pid})
			select {
			case <-done:
				if !tc.wantExit {
					t.Fatal("cleanup killed unrelated process")
				}
			case <-time.After(100 * time.Millisecond):
				if tc.wantExit {
					t.Fatal("matching process survived cleanup")
				}
			}
			t.Log("expected process outcome for pid=" + strconv.Itoa(cmd.Process.Pid))
		})
	}
}

func TestOrphanProcessHandleSurvivesExit(t *testing.T) {
	original, done := auditFirecrackerProcess(t, "sb-original")
	fd, err := openSandboxProcess(original.Process.Pid, "sb-original")
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	_ = original.Process.Kill()
	<-done
	_, otherDone := auditFirecrackerProcess(t, "sb-other")
	for _, sig := range []unix.Signal{unix.SIGINT, unix.SIGKILL} {
		if err = unix.PidfdSendSignal(fd, sig, nil, 0); !errors.Is(err, unix.ESRCH) {
			t.Fatalf("exited handle signal: %v", err)
		}
	}
	select {
	case <-otherDone:
		t.Fatal("unrelated process exited")
	case <-time.After(100 * time.Millisecond):
	}
	t.Log("exited process handle returns ESRCH; unrelated process remains alive")
}
