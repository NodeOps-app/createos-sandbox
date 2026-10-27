package proto

// Shared HTTP headers used by more than one CreateOS component.
const (
	HeaderAPIKey                    = "X-Api-Key"
	HeaderBootstrapToken            = "X-Bootstrap-Token"
	HeaderSandboxID                 = "X-Sandbox-ID"
	HeaderSandboxIngressURLTemplate = "X-CreateOS-Sandbox-Ingress-URL-Template"
)

// ExecRequest is the request sent from host to guest agent to execute a command.
type ExecRequest struct {
	Cmd  string   `json:"cmd"`
	Args []string `json:"args,omitempty"`
	// Env is the per-sandbox env-var map injected by the host's exec
	// handler before the request hits the agent. Users never set this
	// directly — the host populates it from the persistent sandbox
	// envs (sandboxes.envs in the DB). Agent merges into os.Environ().
	Env map[string]string `json:"env,omitempty"`
	// Stream switches the wire protocol from a single buffered
	// ExecResponse to a stream of newline-delimited ExecStreamEvent
	// objects. The agent emits one event per stdout/stderr chunk plus
	// a heartbeat tick, terminating with a final {"exit": N}. Disconnect
	// at any layer kills the command in the VM.
	Stream bool `json:"stream,omitempty"`
	// Stdin is fed to the spawned process's standard input. EOF is
	// signalled on close, so commands like `cat` see a complete input
	// followed by EOF and exit normally. Empty (default) → /dev/null.
	Stdin string `json:"stdin,omitempty"`
}

// ExecResponse is the response from the guest agent after executing a command.
type ExecResponse struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
	Error    string `json:"error,omitempty"`
}

// ExecStreamEvent is one frame of a streaming exec, encoded as a single
// line of NDJSON. Field names match ExecResponse so the same struct can
// parse both worlds — buffered exec returns one ExecResponse; streaming
// returns N ExecStreamEvent lines that you can either consume live or
// reduce into a single ExecResponse-equivalent value.
//
// In any one event exactly one field is meaningful; the rest are zero
// and elided by omitempty. Frame types:
//
//	{"stdout":"..."}     — stdout chunk
//	{"stderr":"..."}     — stderr chunk
//	{"hb":true}          — heartbeat (every 5s; forces a write so a dead
//	                        peer is noticed within ~5s on silent commands)
//	{"exit_code":N}      — terminal frame with the cmd's exit code
//	{"error":"..."}      — agent-level failure (couldn't start cmd, etc.)
type ExecStreamEvent struct {
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"` // pointer so exit 0 isn't elided
	Error    string `json:"error,omitempty"`
	HB       bool   `json:"hb,omitempty"`
}

// SandboxInfo describes a running sandbox.
type SandboxInfo struct {
	ID     string `json:"id"`
	IP     string `json:"ip"`
	Status string `json:"status"`
}
