// Package placementpolicy contains operator-owned placement preferences.
package placementpolicy

import "sync"

// Policy overrides the region for new sandboxes when Region is nonempty.
// PreferredHostIDs are soft preferences used only when both region and shape
// match; eligible hosts outside that list remain fallback candidates.
type Policy struct {
	Region           string
	Shapes           []string
	PreferredHostIDs []string
}

// Policies are loaded from the operator-owned control/sweep YAML.
// Public API requests cannot populate or modify them.
//
// Example:
//
//	"user-id": {
//		Region: "us",
//		Shapes: []string{"s-2vcpu-4gb", "s-4vcpu-8gb"},
//		PreferredHostIDs: []string{"host-a", "host-b"},
//	},
var policies = struct {
	sync.RWMutex
	byUser           map[string]Policy
	crossRegionUsers map[string]bool
}{byUser: map[string]Policy{}}

// Configure replaces the process-wide immutable policy snapshot. Control and
// sweep call it once after loading YAML; copying prevents later config mutation.
func Configure(configured map[string]Policy) {
	next := make(map[string]Policy, len(configured))
	for userID, policy := range configured {
		policy.Shapes = append([]string(nil), policy.Shapes...)
		policy.PreferredHostIDs = append([]string(nil), policy.PreferredHostIDs...)
		next[userID] = policy
	}
	policies.Lock()
	policies.byUser = next
	policies.Unlock()
}

// Lookup returns a defensive copy so callers cannot mutate global policy.
func Lookup(userID string) (Policy, bool) {
	policies.RLock()
	policy, ok := policies.byUser[userID]
	policies.RUnlock()
	if !ok {
		return Policy{}, false
	}
	policy.Shapes = append([]string(nil), policy.Shapes...)
	policy.PreferredHostIDs = append([]string(nil), policy.PreferredHostIDs...)
	return policy, true
}

// RegionForNewSandbox applies the user's configured region and otherwise
// preserves the requested region (including empty, which control later
// defaults to its local region).
func RegionForNewSandbox(userID, requested string) string {
	policy, ok := Lookup(userID)
	if !ok || policy.Region == "" {
		return requested
	}
	return policy.Region
}

// PreferredHosts returns host preferences only when both the configured
// region and one of the configured shapes match the scheduling request.
func PreferredHosts(userID, shape, region string) []string {
	policy, ok := Lookup(userID)
	if !ok || policy.Region != region {
		return nil
	}
	for _, configuredShape := range policy.Shapes {
		if configuredShape == shape {
			return policy.PreferredHostIDs
		}
	}
	return nil
}

// ConfigureCrossRegionUsers installs the operator's capacity-fallback allowlist.
// Empty means all authenticated users. Requests cannot change this policy.
func ConfigureCrossRegionUsers(users []string) {
	enabled := make(map[string]bool, len(users))
	for _, user := range users {
		enabled[user] = true
	}
	policies.Lock()
	policies.crossRegionUsers = enabled
	policies.Unlock()
}

func CrossRegionEnabled(userID string) bool {
	if userID == "" {
		return false
	}
	policies.RLock()
	defer policies.RUnlock()
	return len(policies.crossRegionUsers) == 0 || policies.crossRegionUsers[userID]
}
