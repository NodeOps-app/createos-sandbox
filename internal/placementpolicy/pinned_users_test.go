package placementpolicy

import "testing"

func installTestPolicy(t *testing.T, userID string) {
	t.Helper()
	Configure(map[string]Policy{userID: {
		Region:           "us",
		Shapes:           []string{"small", "medium"},
		PreferredHostIDs: []string{"us-a", "us-b"},
	}})
	t.Cleanup(func() { Configure(nil) })
}

func TestLookupReturnsDefensiveCopy(t *testing.T) {
	const userID = "test-user"
	installTestPolicy(t, userID)

	got, ok := Lookup(userID)
	if !ok {
		t.Fatal("expected policy")
	}
	got.Shapes[0] = "mutated-shape"
	got.PreferredHostIDs[0] = "mutated-host"

	again, _ := Lookup(userID)
	if again.Shapes[0] != "small" || again.PreferredHostIDs[0] != "us-a" {
		t.Fatalf("global policy was mutated: %#v", again)
	}
}

func TestRegionForConfiguredAndOrdinaryUsers(t *testing.T) {
	const userID = "regional-user"
	installTestPolicy(t, userID)

	if got := RegionForNewSandbox(userID, "eu"); got != "us" {
		t.Fatalf("configured user region = %q, want us", got)
	}
	if got := RegionForNewSandbox("ordinary-user", "eu"); got != "eu" {
		t.Fatalf("ordinary region = %q, want eu", got)
	}
}

func TestPreferredHostsRequireMatchingShapeAndRegion(t *testing.T) {
	const userID = "preferred-user"
	installTestPolicy(t, userID)

	if got := PreferredHosts(userID, "small", "eu"); got != nil {
		t.Fatalf("cross-region preferences = %#v, want nil", got)
	}
	if got := PreferredHosts(userID, "large", "us"); got != nil {
		t.Fatalf("unconfigured-shape preferences = %#v, want nil", got)
	}
	if got := PreferredHosts(userID, "small", "us"); len(got) != 2 || got[0] != "us-a" {
		t.Fatalf("matching preferences = %#v", got)
	}
}

func TestCrossRegionUserAllowlist(t *testing.T) {
	t.Cleanup(func() { ConfigureCrossRegionUsers(nil) })
	ConfigureCrossRegionUsers(nil)
	if !CrossRegionEnabled("any-user") || CrossRegionEnabled("") {
		t.Fatal("empty allowlist must enable all authenticated users")
	}
	users := []string{"selected-user"}
	ConfigureCrossRegionUsers(users)
	users[0] = "mutated"
	if !CrossRegionEnabled("selected-user") || CrossRegionEnabled("other-user") || CrossRegionEnabled("mutated") {
		t.Fatal("allowlist did not restrict users or retained mutable input")
	}
}
