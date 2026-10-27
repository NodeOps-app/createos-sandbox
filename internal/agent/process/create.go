package process

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/NodeOps-app/sandbox/internal/agent/childreaper"
)

type ProcessSpec struct {
	Argv []string
	Cwd  string
	Env  map[string]string
}

type PTYSpec struct {
	Argv []string
	Cwd  string
	Env  map[string]string
	Cols uint16
	Rows uint16
}

func (m *Manager) CreateProcess(ctx context.Context, spec ProcessSpec) (CreatedProcess, error) {
	if ctx == nil {
		return CreatedProcess{}, errors.New("process creation context is required")
	}
	argv, cwd, env, err := prepareCommand(spec.Argv, spec.Cwd, spec.Env, false)
	if err != nil {
		return CreatedProcess{}, err
	}
	if err := ctx.Err(); err != nil {
		return CreatedProcess{}, err
	}

	record, err := m.reserveProcess(processModePipes, argv, cwd)
	if err != nil {
		return CreatedProcess{}, err
	}
	cgroup, err := createProcessCgroup(record.id)
	if err != nil {
		return CreatedProcess{}, m.failStart(record, err)
	}
	if err := record.setCgroup(cgroup); err != nil {
		_ = cgroup.remove()
		return CreatedProcess{}, m.failStart(record, err)
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = cwd
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid:     true,
		Cloneflags:  syscall.CLONE_NEWCGROUP,
		UseCgroupFD: true,
		CgroupFD:    cgroup.fd(),
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return CreatedProcess{}, m.failStart(record, err)
	}
	stdout, stdoutWriter, err := os.Pipe()
	if err != nil {
		_ = stdin.Close()
		return CreatedProcess{}, m.failStart(record, err)
	}
	stderr, stderrWriter, err := os.Pipe()
	if err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		_ = stdoutWriter.Close()
		return CreatedProcess{}, m.failStart(record, err)
	}
	cmd.Stdout = stdoutWriter
	cmd.Stderr = stderrWriter
	if err := ctx.Err(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		_ = stdoutWriter.Close()
		_ = stderr.Close()
		_ = stderrWriter.Close()
		return CreatedProcess{}, m.failStart(record, err)
	}
	if err := cmd.Start(); err != nil {
		cgroup.closeAttachFD()
		_ = stdin.Close()
		_ = stdout.Close()
		_ = stdoutWriter.Close()
		_ = stderr.Close()
		_ = stderrWriter.Close()
		return CreatedProcess{}, m.failStart(record, err)
	}
	// Only the child should retain the write ends. Keeping a parent copy open
	// would prevent capture from observing EOF after the process tree exits.
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()
	cgroup.closeAttachFD()
	if err := record.started(cmd.Process.Pid, cmd.Process.Pid, stdin, nil); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = stdin.Close()
		_ = stdout.Close()
		_ = stderr.Close()
		return CreatedProcess{}, m.failStart(record, err)
	}

	var captures sync.WaitGroup
	captureErrors := make(chan error, 2)
	captures.Add(2)
	go captureProcessOutput(record, processOutputStdout, stdout, &captures, captureErrors)
	go captureProcessOutput(record, processOutputStderr, stderr, &captures, captureErrors)
	go m.reap(record, cmd, &captures, captureErrors)
	log.Printf("agent.process event=started process_id=%s kind=%s pid=%d", record.id, ProcessKind, cmd.Process.Pid)

	return CreatedProcess{ID: string(record.id), PID: cmd.Process.Pid}, nil
}

func (m *Manager) CreatePTY(ctx context.Context, spec PTYSpec) (CreatedProcess, error) {
	if ctx == nil {
		return CreatedProcess{}, errors.New("PTY creation context is required")
	}
	if spec.Cols == 0 {
		spec.Cols = 80
	}
	if spec.Rows == 0 {
		spec.Rows = 24
	}
	argv := spec.Argv
	if len(argv) == 0 {
		argv = defaultPTYArgv()
	}
	preparedArgv, cwd, env, err := prepareCommand(argv, spec.Cwd, spec.Env, true)
	if err != nil {
		return CreatedProcess{}, err
	}
	if err := ctx.Err(); err != nil {
		return CreatedProcess{}, err
	}

	record, err := m.reserveProcess(processModePTY, preparedArgv, cwd)
	if err != nil {
		return CreatedProcess{}, err
	}
	cgroup, err := createProcessCgroup(record.id)
	if err != nil {
		return CreatedProcess{}, m.failStart(record, err)
	}
	if err := record.setCgroup(cgroup); err != nil {
		_ = cgroup.remove()
		return CreatedProcess{}, m.failStart(record, err)
	}
	master, slave, err := openPTY()
	if err != nil {
		return CreatedProcess{}, m.failStart(record, err)
	}
	if err := setWinsize(master, spec.Rows, spec.Cols); err != nil {
		_ = master.Close()
		_ = slave.Close()
		return CreatedProcess{}, m.failStart(record, err)
	}

	cmd := exec.Command(preparedArgv[0], preparedArgv[1:]...)
	cmd.Dir = cwd
	cmd.Env = env
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:      true,
		Setctty:     true,
		Cloneflags:  syscall.CLONE_NEWCGROUP,
		UseCgroupFD: true,
		CgroupFD:    cgroup.fd(),
	}
	if err := ctx.Err(); err != nil {
		_ = master.Close()
		_ = slave.Close()
		return CreatedProcess{}, m.failStart(record, err)
	}
	if err := cmd.Start(); err != nil {
		cgroup.closeAttachFD()
		_ = master.Close()
		_ = slave.Close()
		return CreatedProcess{}, m.failStart(record, err)
	}
	cgroup.closeAttachFD()
	_ = slave.Close()
	if err := record.started(cmd.Process.Pid, cmd.Process.Pid, nil, master); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = master.Close()
		return CreatedProcess{}, m.failStart(record, err)
	}

	var captures sync.WaitGroup
	captureErrors := make(chan error, 1)
	captures.Add(1)
	go captureProcessOutput(record, processOutputPTY, master, &captures, captureErrors)
	go m.reap(record, cmd, &captures, captureErrors)
	log.Printf("agent.process event=started process_id=%s kind=%s pid=%d", record.id, PTYKind, cmd.Process.Pid)

	return CreatedProcess{ID: string(record.id), PID: cmd.Process.Pid}, nil
}

func (m *Manager) failStart(record *processRecord, cause error) error {
	log.Printf("agent.process event=start_failed process_id=%s kind=%s", record.id, processKindName(record.mode))
	record.finish(processStateFailed, processResult{
		Error:    cause.Error(),
		ExitedAt: m.now(),
	})
	record.closeRuntimeIO()
	record.finishOutput()
	if cgroup := record.processCgroup(); cgroup != nil {
		cgroup.closeAttachFD()
		_ = cgroup.remove()
	}
	m.remove(record.id)
	return cause
}

func (m *Manager) reap(
	record *processRecord,
	cmd *exec.Cmd,
	captures *sync.WaitGroup,
	captureErrors <-chan error,
) {
	// Observe the leader independently from its descendants. stdout/stderr use
	// parent-owned pipe readers, so Wait cannot close them; capture continues
	// until every descendant releases the inherited writer. PTYs similarly
	// remain readable through the master until the complete session tree exits.
	waitErr := cmd.Wait()

	result := resultFromWait(cmd, waitErr, m.now())
	if cmd.Process != nil {
		if status, ok := childreaper.TakeStatus(waitErr, cmd.Process.Pid); ok {
			result = resultFromWaitStatus(status, m.now())
		}
		childreaper.Forget(cmd.Process.Pid)
	}
	record.finish(processStateExited, result)

	// Output completion is deliberately separate from leader completion.
	// Connect streams remain open for descendant output, while leader-scoped
	// wait returns as soon as cmd.Wait observes the top-level process.
	captures.Wait()
	record.closeRuntimeIO()
	record.finishOutput()
	for {
		select {
		case err := <-captureErrors:
			if err != nil {
				log.Printf("agent.process event=capture_failed process_id=%s error=%q", record.id, err)
			}
		default:
			exitCode := "null"
			if result.ExitCode != nil {
				exitCode = fmt.Sprintf("%d", *result.ExitCode)
			}
			log.Printf("agent.process event=exited process_id=%s kind=%s pid=%d exit_code=%s signal=%q capture_error=%t",
				record.id, processKindName(record.mode), cmd.Process.Pid, exitCode, result.Signal, result.Error != "")
			if cgroup := record.processCgroup(); cgroup != nil {
				_ = cgroup.removeIfEmpty()
			}
			return
		}
	}
}

func captureProcessOutput(
	record *processRecord,
	stream processOutputStream,
	reader io.Reader,
	done *sync.WaitGroup,
	errs chan<- error,
) {
	defer done.Done()
	buffer := make([]byte, maxProcessOutputEventBytes)
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			if _, appendErr := record.appendOutput(stream, buffer[:n]); appendErr != nil {
				errs <- appendErr
				return
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, syscall.EIO) {
				errs <- fmt.Errorf("capture process output: %w", err)
			}
			return
		}
	}
}

func resultFromWait(cmd *exec.Cmd, waitErr error, exitedAt time.Time) processResult {
	result := processResult{ExitedAt: exitedAt}
	if cmd.ProcessState == nil {
		if waitErr != nil {
			result.Error = waitErr.Error()
		}
		return result
	}

	if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		result.Signal = status.Signal().String()
		return result
	}
	exitCode := cmd.ProcessState.ExitCode()
	result.ExitCode = &exitCode
	if waitErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(waitErr, &exitErr) {
			result.Error = waitErr.Error()
		}
	}
	return result
}

func resultFromWaitStatus(status syscall.WaitStatus, exitedAt time.Time) processResult {
	result := processResult{ExitedAt: exitedAt}
	if status.Signaled() {
		result.Signal = status.Signal().String()
		return result
	}
	exitCode := status.ExitStatus()
	result.ExitCode = &exitCode
	return result
}

func prepareCommand(argv []string, cwd string, overrides map[string]string, pty bool) ([]string, string, []string, error) {
	if len(argv) == 0 || argv[0] == "" {
		return nil, "", nil, errors.New("process argv is required")
	}
	preparedArgv := append([]string(nil), argv...)
	for _, arg := range preparedArgv {
		if strings.IndexByte(arg, 0) >= 0 {
			return nil, "", nil, errors.New("process argv contains NUL")
		}
	}
	if cwd == "" {
		cwd = "/root"
	}
	if strings.IndexByte(cwd, 0) >= 0 {
		return nil, "", nil, errors.New("process cwd contains NUL")
	}

	envMap := make(map[string]string)
	for _, entry := range os.Environ() {
		key, value, found := strings.Cut(entry, "=")
		if found {
			envMap[key] = value
		}
	}
	for key, value := range overrides {
		if key == "" || strings.ContainsAny(key, "=\x00") || strings.IndexByte(value, 0) >= 0 {
			return nil, "", nil, errors.New("invalid process environment")
		}
		envMap[key] = value
	}
	if pty {
		if _, specified := overrides["TERM"]; !specified {
			envMap["TERM"] = "xterm-256color"
		}
	}
	keys := make([]string, 0, len(envMap))
	for key := range envMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	env := make([]string, 0, len(keys))
	for _, key := range keys {
		env = append(env, key+"="+envMap[key])
	}
	return preparedArgv, cwd, env, nil
}

func defaultPTYArgv() []string {
	if _, err := os.Stat("/bin/bash"); err == nil {
		return []string{"/bin/bash", "-i", "-l"}
	}
	return []string{"/bin/sh", "-l"}
}
