package database

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/knadh/goyesql/v2"
)

// TestSandboxRowQueriesShareProjection guards the positional contract between
// database queries and models.scanSandbox. A field added to one full sandbox
// projection must be added, in the same position, to every matching query.
func TestSandboxRowQueriesShareProjection(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("queries.sql")
	if err != nil {
		t.Fatal(err)
	}
	queries := splitNamedQueries(string(raw))
	want := sandboxProjection(t, "getSandbox", queries["getSandbox"])
	var names []string
	for name, query := range queries {
		// Full sandbox-row queries share this distinctive prefix and include
		// the VM sizing fields. Narrow route/billing projections intentionally
		// use different scanners and are excluded.
		normalized := strings.Join(strings.Fields(strings.ReplaceAll(query, "s.", "")), "")
		if (strings.Contains(normalized, "SELECTid,COALESCE(host_id,'')") ||
			strings.Contains(normalized, "RETURNINGid,COALESCE(host_id,''),status,mode")) &&
			strings.Contains(normalized, "vcpu,mem_mib,disk_mib") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if len(names) < 2 {
		t.Fatalf("found only %d full sandbox-row queries; discovery is broken", len(names))
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			got := sandboxProjection(t, name, queries[name])
			if got != want {
				t.Errorf("full sandbox projection differs from getSandbox\nwant: %s\n got: %s", want, got)
			}
		})
	}
}

var queryNameRE = regexp.MustCompile(`(?m)^-- name: ([A-Za-z0-9]+)\s*$`)

func splitNamedQueries(sql string) map[string]string {
	matches := queryNameRE.FindAllStringSubmatchIndex(sql, -1)
	out := make(map[string]string, len(matches))
	for i, match := range matches {
		end := len(sql)
		if i+1 < len(matches) {
			end = matches[i+1][0]
		}
		out[sql[match[2]:match[3]]] = sql[match[1]:end]
	}
	return out
}

func sandboxProjection(t *testing.T, name, query string) string {
	t.Helper()
	if query == "" {
		t.Fatalf("query %q not found", name)
	}
	var projection string
	if i := strings.LastIndex(query, "RETURNING "); i >= 0 {
		projection = query[i+len("RETURNING "):]
		if end := strings.IndexByte(projection, ';'); end >= 0 {
			projection = projection[:end]
		}
	} else {
		start := strings.Index(query, "SELECT ")
		if start < 0 {
			t.Fatalf("query %q has no SELECT or RETURNING projection", name)
		}
		projection = query[start+len("SELECT "):]
		from := strings.Index(projection, "\n  FROM sandboxes")
		if from < 0 {
			t.Fatalf("query %q has no FROM sandboxes after projection", name)
		}
		projection = projection[:from]
	}
	projection = strings.ReplaceAll(projection, "s.", "")
	return strings.Join(strings.Fields(projection), "")
}

func TestAllNamedQueriesParseAndAreUnique(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("queries.sql")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := goyesql.ParseBytes(raw)
	if err != nil {
		t.Fatalf("parse all named queries: %v", err)
	}
	matches := queryNameRE.FindAllStringSubmatch(string(raw), -1)
	seen := make(map[string]int, len(matches))
	for _, match := range matches {
		seen[match[1]]++
	}
	var duplicates []string
	for name, count := range seen {
		if count > 1 {
			duplicates = append(duplicates, name)
		}
	}
	sort.Strings(duplicates)
	if len(duplicates) > 0 {
		t.Fatalf("duplicate named queries: %v", duplicates)
	}
	if len(parsed) != len(matches) {
		t.Fatalf("parsed %d queries from %d declarations", len(parsed), len(matches))
	}
	for name, query := range parsed {
		if strings.TrimSpace(query.Query) == "" {
			t.Errorf("query %q has an empty SQL body", name)
		}
	}
}
