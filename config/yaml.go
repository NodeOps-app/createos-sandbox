package config

import (
	"fmt"
	"os"
	"time"

	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"
)

// loadYAML strictly decodes the file at path into out. Unknown keys fail.
// An empty path is a no-op (out is left untouched).
func loadYAML(path string, out any) error {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open config %s: %w", path, err)
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("parse config %s: %w", path, err)
	}
	return nil
}

// pickStr returns the explicit CLI/env value if set, else the YAML value if
// non-nil, else the flag's default (via c.String).
func pickStr(c *cli.Context, name string, yaml *string) string {
	if c.IsSet(name) {
		return c.String(name)
	}
	if yaml != nil {
		return *yaml
	}
	return c.String(name)
}

func pickInt(c *cli.Context, name string, yaml *int) int {
	if c.IsSet(name) {
		return c.Int(name)
	}
	if yaml != nil {
		return *yaml
	}
	return c.Int(name)
}

func pickInt64(c *cli.Context, name string, yaml *int64) int64 {
	if c.IsSet(name) {
		return c.Int64(name)
	}
	if yaml != nil {
		return *yaml
	}
	return c.Int64(name)
}

func pickBool(c *cli.Context, name string, yaml *bool) bool {
	if c.IsSet(name) {
		return c.Bool(name)
	}
	if yaml != nil {
		return *yaml
	}
	return c.Bool(name)
}

func pickDur(c *cli.Context, name string, yaml *time.Duration) time.Duration {
	if c.IsSet(name) {
		return c.Duration(name)
	}
	if yaml != nil {
		return *yaml
	}
	return c.Duration(name)
}
