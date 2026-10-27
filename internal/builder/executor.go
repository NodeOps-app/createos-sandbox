package builder

import "context"

// BuildSpec is everything an isolated executor needs for one template build.
type BuildSpec struct {
	TplID      string
	Dockerfile string
	Grants     *Grants
	ControlURL string
	SizeCapMiB int64
}

// Executor runs one template build and returns only after it reaches a
// terminal state. Implementations must clean up their isolated runtime.
type Executor interface {
	Run(context.Context, BuildSpec) error
}

// BuildSandbox identifies a disposable sandbox discovered by its durable
// builder labels. It is deliberately small so janitor recovery does not rely
// on executor-local state lost during a restart.
type BuildSandbox struct {
	ID         string
	TemplateID string
	ProcessID  string
}

// SandboxJanitor is implemented by executors whose build environments can
// outlive the builder process. Service uses it opportunistically; keeping it
// separate from Executor preserves lightweight test and future executors.
type SandboxJanitor interface {
	ListBuildSandboxes(context.Context) ([]BuildSandbox, error)
	BuildProcessFinished(context.Context, BuildSandbox) (bool, error)
	DestroyBuildSandbox(context.Context, string) error
}
