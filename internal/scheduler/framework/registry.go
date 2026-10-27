package framework

import (
	"fmt"
	"sync"
)

// PipelineSpec is the YAML/config-friendly description of a pipeline,
// resolvable against a Registry into a concrete Pipeline.
type PipelineSpec struct {
	Filters  []string     `yaml:"filters" json:"filters"`
	Scorers  []ScorerSpec `yaml:"scorers" json:"scorers"`
	Reserver string       `yaml:"reserver" json:"reserver"`
}

// ScorerSpec selects a registered scorer with an optional weight override.
// Weight==0 falls back to the Scorer's built-in Weight().
type ScorerSpec struct {
	Name   string `yaml:"name" json:"name"`
	Weight int    `yaml:"weight" json:"weight"`
}

// Registry maps plugin names to factories. Construct with NewRegistry,
// register built-ins via plugins.RegisterBuiltins, then BuildPipeline.
type Registry struct {
	mu        sync.RWMutex
	filters   map[string]func() Filter
	scorers   map[string]func() Scorer
	reservers map[string]func() Reserver
}

func NewRegistry() *Registry {
	return &Registry{
		filters:   make(map[string]func() Filter),
		scorers:   make(map[string]func() Scorer),
		reservers: make(map[string]func() Reserver),
	}
}

func (r *Registry) RegisterFilter(name string, factory func() Filter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.filters[name] = factory
}

func (r *Registry) RegisterScorer(name string, factory func() Scorer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scorers[name] = factory
}

func (r *Registry) RegisterReserver(name string, factory func() Reserver) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reservers[name] = factory
}

// BuildPipeline resolves spec against r's registered plugins.
func (r *Registry) BuildPipeline(spec PipelineSpec) (*Pipeline, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p := &Pipeline{}
	for _, name := range spec.Filters {
		factory, ok := r.filters[name]
		if !ok {
			return nil, fmt.Errorf("%w: filter %q", ErrUnknownPlugin, name)
		}
		p.Filters = append(p.Filters, factory())
	}
	for _, ss := range spec.Scorers {
		factory, ok := r.scorers[ss.Name]
		if !ok {
			return nil, fmt.Errorf("%w: scorer %q", ErrUnknownPlugin, ss.Name)
		}
		p.Scorers = append(p.Scorers, factory())
		p.ScorerWeights = append(p.ScorerWeights, ss.Weight)
	}
	if spec.Reserver != "" {
		factory, ok := r.reservers[spec.Reserver]
		if !ok {
			return nil, fmt.Errorf("%w: reserver %q", ErrUnknownPlugin, spec.Reserver)
		}
		p.Reserver = factory()
	}
	return p, nil
}
