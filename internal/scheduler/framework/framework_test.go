package framework

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/NodeOps-app/sandbox/models"
)

type passFilter struct{ name string }

func (f *passFilter) Name() string { return f.name }
func (f *passFilter) Filter(*Request, *models.Host) (bool, string) {
	return true, ""
}

type rejectFilter struct{ rejectID string }

func (f *rejectFilter) Name() string { return "reject-" + f.rejectID }
func (f *rejectFilter) Filter(_ *Request, h *models.Host) (bool, string) {
	if h.ID == f.rejectID {
		return false, "rejected"
	}
	return true, ""
}

type fixedScorer struct {
	name   string
	score  int
	weight int
}

func (s *fixedScorer) Name() string                     { return s.name }
func (s *fixedScorer) Score(*Request, *models.Host) int { return s.score }
func (s *fixedScorer) Weight() int                      { return s.weight }

type idScorer struct{ winner string }

func (s *idScorer) Name() string { return "id" }
func (s *idScorer) Score(_ *Request, h *models.Host) int {
	if h.ID == s.winner {
		return 100
	}
	return 0
}
func (s *idScorer) Weight() int { return 1 }

type recordingReserver struct {
	reserved map[string]string // sbID → hostID
	failOn   string
	conflict bool
}

func (r *recordingReserver) Name() string { return "rec" }
func (r *recordingReserver) Reserve(_ context.Context, sbID string, _ *Request, h *models.Host) error {
	if h.ID == r.failOn {
		if r.conflict {
			return ErrConflict
		}
		return errors.New("hard error")
	}
	if r.reserved == nil {
		r.reserved = make(map[string]string)
	}
	r.reserved[sbID] = h.ID
	return nil
}
func (r *recordingReserver) Release(_ context.Context, sbID string) error {
	delete(r.reserved, sbID)
	return nil
}
func (r *recordingReserver) Reconcile(_, _ map[string]bool, _ time.Time) {}
func (r *recordingReserver) PendingIDs() []string {
	out := make([]string, 0, len(r.reserved))
	for id := range r.reserved {
		out = append(out, id)
	}
	return out
}

func mkHosts(ids ...string) []models.Host {
	out := make([]models.Host, len(ids))
	for i, id := range ids {
		out[i] = models.Host{ID: id, Status: "active", MemCapacityMib: 1000}
	}
	return out
}

func TestSchedule_NoHosts(t *testing.T) {
	p := &Pipeline{}
	_, err := p.Schedule(context.Background(), "sb_test", &Request{}, nil)
	if !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("err = %v, want ErrNoCapacity", err)
	}
}

func TestSchedule_AllFiltered(t *testing.T) {
	p := &Pipeline{
		Filters: []Filter{&rejectFilter{rejectID: "h1"}, &rejectFilter{rejectID: "h2"}},
	}
	_, err := p.Schedule(context.Background(), "sb_test", &Request{}, mkHosts("h1", "h2"))
	if !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("err = %v, want ErrNoCapacity", err)
	}
}

func TestSchedule_NoReserver_PicksHighest(t *testing.T) {
	p := &Pipeline{
		Scorers: []Scorer{&idScorer{winner: "h2"}},
	}
	d, err := p.Schedule(context.Background(), "sb_test", &Request{}, mkHosts("h1", "h2", "h3"))
	if err != nil {
		t.Fatal(err)
	}
	if d.HostID != "h2" {
		t.Errorf("HostID = %q, want h2", d.HostID)
	}
}

func TestSchedule_ConflictFallsThrough(t *testing.T) {
	r := &recordingReserver{failOn: "h2", conflict: true}
	p := &Pipeline{
		Scorers:  []Scorer{&idScorer{winner: "h2"}},
		Reserver: r,
	}
	d, err := p.Schedule(context.Background(), "sb_test", &Request{}, mkHosts("h1", "h2", "h3"))
	if err != nil {
		t.Fatal(err)
	}
	if d.HostID == "h2" {
		t.Error("expected fallthrough away from h2")
	}
	if r.reserved["sb_test"] == "" {
		t.Error("expected reservation to be recorded")
	}
}

func TestSchedule_PreferredHostWinsBeforeScoring(t *testing.T) {
	p := &Pipeline{Scorers: []Scorer{&idScorer{winner: "ordinary"}}}
	d, err := p.Schedule(context.Background(), "sb_test", &Request{
		PreferredHostIDs: []string{"preferred"},
	}, mkHosts("ordinary", "preferred"))
	if err != nil {
		t.Fatal(err)
	}
	if d.HostID != "preferred" {
		t.Fatalf("HostID = %q, want preferred", d.HostID)
	}
}

func TestSchedule_FilteredPreferredHostFallsBack(t *testing.T) {
	p := &Pipeline{
		Filters: []Filter{&rejectFilter{rejectID: "preferred"}},
	}
	d, err := p.Schedule(context.Background(), "sb_test", &Request{
		PreferredHostIDs: []string{"preferred"},
	}, mkHosts("preferred", "fallback"))
	if err != nil {
		t.Fatal(err)
	}
	if d.HostID != "fallback" {
		t.Fatalf("HostID = %q, want fallback", d.HostID)
	}
}

func TestSchedule_PreferredReservationConflictFallsBack(t *testing.T) {
	r := &recordingReserver{failOn: "preferred", conflict: true}
	p := &Pipeline{Reserver: r}
	d, err := p.Schedule(context.Background(), "sb_test", &Request{
		PreferredHostIDs: []string{"preferred"},
	}, mkHosts("preferred", "fallback"))
	if err != nil {
		t.Fatal(err)
	}
	if d.HostID != "fallback" {
		t.Fatalf("HostID = %q, want fallback", d.HostID)
	}
}

func TestSchedule_HardErrorPropagates(t *testing.T) {
	r := &recordingReserver{failOn: "h1", conflict: false}
	p := &Pipeline{Reserver: r}
	_, err := p.Schedule(context.Background(), "sb_test", &Request{}, mkHosts("h1"))
	if err == nil || errors.Is(err, ErrConflict) || errors.Is(err, ErrNoCapacity) {
		t.Fatalf("err = %v, want hard error", err)
	}
}

func TestRegistry_BuildPipeline(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterFilter("pass", func() Filter { return &passFilter{name: "pass"} })
	reg.RegisterScorer("fixed5", func() Scorer { return &fixedScorer{name: "fixed5", score: 5, weight: 2} })
	reg.RegisterReserver("rec", func() Reserver { return &recordingReserver{} })

	p, err := reg.BuildPipeline(PipelineSpec{
		Filters:  []string{"pass"},
		Scorers:  []ScorerSpec{{Name: "fixed5", Weight: 0}, {Name: "fixed5", Weight: 10}},
		Reserver: "rec",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Filters) != 1 || len(p.Scorers) != 2 || p.Reserver == nil {
		t.Errorf("pipeline shape wrong: %+v", p)
	}
	if p.ScorerWeights[0] != 0 || p.ScorerWeights[1] != 10 {
		t.Errorf("ScorerWeights = %v", p.ScorerWeights)
	}
}

func TestRegistry_UnknownPlugin(t *testing.T) {
	reg := NewRegistry()
	_, err := reg.BuildPipeline(PipelineSpec{Filters: []string{"nope"}})
	if !errors.Is(err, ErrUnknownPlugin) {
		t.Errorf("err = %v, want ErrUnknownPlugin", err)
	}
}
