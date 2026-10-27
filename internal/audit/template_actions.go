package audit

const (
	ActionTemplateSubmit        Action = "template.submit"
	ActionTemplateDelete        Action = "template.delete"
	ActionTemplateBuildStart    Action = "template.build.start"
	ActionTemplateBuildComplete Action = "template.build.complete"
)

type TemplateSubmit struct {
	TemplateID      string `json:"template_id"`
	Name            string `json:"name"`
	BaseImage       string `json:"base_image"`
	DockerfileBytes int64  `json:"dockerfile_bytes,omitempty"`
	// NEVER include: raw Dockerfile, ARG defaults, build secrets.
}

func (TemplateSubmit) isAuditMetadata() {}

type TemplateDelete struct {
	TemplateID string `json:"template_id"`
	Name       string `json:"name,omitempty"`
}

func (TemplateDelete) isAuditMetadata() {}

// Builder-emitted: Actor is "builder:<id>", UserID is the template owner.
type TemplateBuildStart struct {
	TemplateID string `json:"template_id"`
	Name       string `json:"name,omitempty"`
	Attempt    int    `json:"attempt"`
	BuilderID  string `json:"builder_id"`
}

func (TemplateBuildStart) isAuditMetadata() {}

type TemplateBuildComplete struct {
	TemplateID string  `json:"template_id"`
	Name       string  `json:"name,omitempty"`
	Attempt    int     `json:"attempt"`
	Status     string  `json:"status"` // "ready"|"failed"
	DurationS  float64 `json:"duration_seconds"`
	// First-line only — full error logs may carry secrets from build output.
	ErrorClass string `json:"error_class,omitempty"`
}

func (TemplateBuildComplete) isAuditMetadata() {}
