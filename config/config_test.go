package config

import (
	"bytes"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/urfave/cli/v2"
)

func TestNoDirectOSGetenv(t *testing.T) {
	t.Parallel()
	root := ".."
	needle := []byte("os." + "Getenv(")
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".claude", ".git", ".jj", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(body, needle) {
			t.Errorf("%s reads configuration directly from the process environment; use YAML/CLI resolution", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestNoLegacyFCPrefix(t *testing.T) {
	t.Parallel()
	root := ".."
	needle := []byte("F" + "C_")
	textExtensions := map[string]bool{
		".c": true, ".config": true, ".go": true, ".h": true,
		".md": true, ".sh": true, ".yaml": true, ".yml": true,
	}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".claude", ".git", ".jj", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !textExtensions[filepath.Ext(path)] {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(body, needle) {
			t.Errorf("%s contains the retired project prefix", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestNoLegacyProjectName(t *testing.T) {
	t.Parallel()
	root := ".."
	legacyNames := [][]byte{
		[]byte("f" + "c-spawn"),
		[]byte("f" + "cspawn"),
		[]byte("f" + "c_spawn"),
	}
	textExtensions := map[string]bool{
		".c": true, ".config": true, ".go": true, ".h": true,
		".md": true, ".py": true, ".sh": true, ".yaml": true, ".yml": true,
	}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".claude", ".git", ".jj", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !textExtensions[filepath.Ext(path)] && filepath.Base(path) != "Makefile" {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		body = bytes.ToLower(body)
		for _, legacyName := range legacyNames {
			if bytes.Contains(body, legacyName) {
				t.Errorf("%s contains the retired project name", path)
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestExampleConfigsMatchSchemas(t *testing.T) {
	t.Parallel()
	examples := []struct {
		name string
		out  any
	}{
		{"audit-worker.yaml", &AuditWorkerFile{}},
		{"billing-worker.yaml", &BillingWorkerFile{}},
		{"builder.yaml", &BuilderFile{}},
		{"control.yaml", &ControlFile{}},
		{"gateway.yaml", &GatewayFile{}},
		{"host.yaml", &ServeFile{}},
		{"hostproxy.yaml", &ProxyFile{}},
		{"ingress.yaml", &IngressFile{}},
		{"relay.yaml", &RelayFile{}},
		{"scheduler.yaml", &SchedulerFile{}},
		{"sweep.yaml", &SweepFile{}},
		{"ttlevict.yaml", &TTLEvictFile{}},
	}
	for _, example := range examples {
		example := example
		t.Run(example.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join("..", "examples", "config", example.name)
			if err := loadYAML(path, example.out); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSweepYAMLAndCLIStayInSync(t *testing.T) {
	path := filepath.Join("..", "examples", "config", "sweep.yaml")
	c := configContext(t, SweepFlags(), "--config", path)
	cfg, err := SweepFromContext(c)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StuckTransitionAge != 15*time.Minute || cfg.DryRun {
		t.Fatalf("YAML values not applied: age=%s dry_run=%v", cfg.StuckTransitionAge, cfg.DryRun)
	}

	c = configContext(t, SweepFlags(), "--config", path, "--stuck-transition-age", "2m", "--dry-run")
	cfg, err = SweepFromContext(c)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StuckTransitionAge != 2*time.Minute || !cfg.DryRun {
		t.Fatalf("CLI values did not override YAML: age=%s dry_run=%v", cfg.StuckTransitionAge, cfg.DryRun)
	}
}

func TestTTLEvictYAMLAndCLIStayInSync(t *testing.T) {
	path := filepath.Join("..", "examples", "config", "ttlevict.yaml")
	c := configContext(t, TTLEvictFlags(), "--config", path)
	cfg, err := TTLEvictFromContext(c)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxAge != time.Hour || cfg.DryRun {
		t.Fatalf("YAML values not applied: max_age=%s dry_run=%v", cfg.MaxAge, cfg.DryRun)
	}

	c = configContext(t, TTLEvictFlags(), "--config", path, "--max-age", "30m", "--dry-run")
	cfg, err = TTLEvictFromContext(c)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxAge != 30*time.Minute || !cfg.DryRun {
		t.Fatalf("CLI values did not override YAML: max_age=%s dry_run=%v", cfg.MaxAge, cfg.DryRun)
	}
}

func configContext(t *testing.T, flags []cli.Flag, args ...string) *cli.Context {
	t.Helper()
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	for _, cliFlag := range flags {
		if err := cliFlag.Apply(set); err != nil {
			t.Fatal(err)
		}
	}
	if err := set.Parse(args); err != nil {
		t.Fatal(err)
	}
	return cli.NewContext(cli.NewApp(), set, nil)
}

func TestEnabledCrossRegionUsers(t *testing.T) {
	for _, tc := range []struct {
		name, yaml string
		count      int
	}{
		{"omitted", "region: us\n", 0},
		{"all", "region: us\nenabled_cross_region_users: []\n", 0},
		{"selected", "region: us\nenabled_cross_region_users: [user-a]\n", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "control.yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := ControlFromContext(configContext(t, ControlFlags(), "--config", path))
			if err != nil {
				t.Fatal(err)
			}
			if len(cfg.EnabledCrossRegionUsers) != tc.count {
				t.Fatalf("users = %v", cfg.EnabledCrossRegionUsers)
			}
		})
	}
}
