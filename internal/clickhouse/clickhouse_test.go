package clickhouse

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

type countingReader struct {
	io.Reader
	bytes int
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.bytes += n
	return n, err
}

func TestLogResponseByteLimit(t *testing.T) {
	line, err := json.Marshal(chRow{TplID: "tpl_test", TS: "2026-11-13 00:00:00.000000", Line: strings.Repeat("x", MaxLineBytes), Attempt: 1})
	if err != nil {
		t.Fatal(err)
	}
	raw := string(line) + "\n"
	t.Run("ordinary", func(t *testing.T) {
		rows, err := parseJSONEachRow(strings.NewReader(raw))
		if err != nil || len(rows) != 1 || len(rows[0].Line) != MaxLineBytes {
			t.Fatalf("ordinary logs: rows=%d err=%v", len(rows), err)
		}
	})
	t.Run("aggregate", func(t *testing.T) {
		r := &countingReader{Reader: strings.NewReader(strings.Repeat(raw, MaxResponseBytes/len(raw)+2))}
		rows, err := parseJSONEachRow(r)
		if !errors.Is(err, ErrResponseTooLarge) || rows != nil {
			t.Fatalf("oversized response returned partial logs: %d %v", len(rows), err)
		}
		if r.bytes > MaxResponseBytes+1 {
			t.Fatalf("read past byte bound: %d", r.bytes)
		}
	})
	t.Run("oversized-row", func(t *testing.T) {
		_, err := parseJSONEachRow(strings.NewReader(strings.Repeat("x", MaxLineBytes*6+4097)))
		if !errors.Is(err, ErrResponseTooLarge) {
			t.Fatalf("oversized row: %v", err)
		}
	})
	t.Run("escaped-line", func(t *testing.T) {
		raw, err := json.Marshal(chRow{Line: strings.Repeat("\x00", MaxLineBytes)})
		if err != nil {
			t.Fatal(err)
		}
		rows, err := parseJSONEachRow(strings.NewReader(string(raw) + "\n"))
		if err != nil || len(rows) != 1 || len(rows[0].Line) != MaxLineBytes {
			t.Fatalf("escaped valid line rejected: %v", err)
		}
	})
}
