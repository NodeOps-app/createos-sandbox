package handlers

import (
	"fmt"
	"slices"
	"strings"
)

// egressPresetVersion changes when a preset's expanded rules change. The
// catalog intentionally lives in control: hosts continue to receive and
// enforce only the existing domain/IP/CIDR rule grammar.
const egressPresetVersion = "2026-09-25"

var egressPresets = map[string][]string{
	"@apt-debian": {
		"deb.debian.org",
		"security.debian.org",
	},
	"@apt-ubuntu": {
		"*.ubuntu.com",
	},
	"@crates": {
		"crates.io",
		"static.crates.io",
		"index.crates.io",
	},
	"@dns": {
		"1.1.1.1:53",
		"8.8.8.8:53",
	},
	"@github": {
		"github.com",
		"*.github.com",
		"*.githubusercontent.com",
		"codeload.github.com",
	},
	"@go": {
		"proxy.golang.org",
		"sum.golang.org",
		"storage.googleapis.com",
	},
	"@npm": {
		"registry.npmjs.org",
		"*.npmjs.org",
		"registry.yarnpkg.com",
	},
	"@pypi": {
		"pypi.org",
		"files.pythonhosted.org",
		"*.pythonhosted.org",
	},
}

func egressPresetNames() []string {
	names := make([]string, 0, len(egressPresets))
	for name := range egressPresets {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// expandEgressPresets returns the concrete rule list hosts already know how
// to enforce. It also normalises whitespace and removes duplicates while
// preserving first-seen order. Any token beginning with '@' is reserved for
// presets, so misspellings fail closed instead of becoming bogus domains.
func expandEgressPresets(rules []string) ([]string, error) {
	expanded := make([]string, 0, len(rules))
	seen := make(map[string]struct{}, len(rules))
	appendRule := func(rule string) {
		if _, ok := seen[rule]; ok {
			return
		}
		seen[rule] = struct{}{}
		expanded = append(expanded, rule)
	}

	for _, raw := range rules {
		rule := strings.TrimSpace(raw)
		if rule == "" {
			continue
		}
		if !strings.HasPrefix(rule, "@") {
			appendRule(rule)
			continue
		}
		preset, ok := egressPresets[rule]
		if !ok {
			return nil, fmt.Errorf("unknown egress preset %q; valid presets: %s",
				rule, strings.Join(egressPresetNames(), ", "))
		}
		for _, concrete := range preset {
			appendRule(concrete)
		}
	}
	return expanded, nil
}

func egressPresetCatalog() map[string][]string {
	out := make(map[string][]string, len(egressPresets))
	for name, rules := range egressPresets {
		out[name] = slices.Clone(rules)
	}
	return out
}
