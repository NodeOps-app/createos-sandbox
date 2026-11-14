// Package clickhouse stores and reads template build logs through the
// ClickHouse HTTP interface using JSONEachRow. Control handlers provide
// authenticated ingestion and user-facing log reads; schema migrations are
// applied separately.
package clickhouse

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// MaxLineBytes caps any single log line. Larger lines are truncated
// at the writer; the truncation marker is appended so the user knows.
const MaxLineBytes = 16 * 1024

// MaxResponseBytes bounds encoded log history per fetch, including JSON escaping.
// A row count alone permits GiB-sized responses from tenant-generated build logs.
const MaxResponseBytes = 8 * 1024 * 1024

var ErrResponseTooLarge = errors.New("build log response exceeds byte limit")

// Line is one row in build_logs.
type Line struct {
	TplID   string    `json:"-"`
	TS      time.Time `json:"-"`
	Level   string    `json:"-"`
	Line    string    `json:"-"`
	Attempt uint8     `json:"-"` // 1-based; matches templates.attempts at the moment the runner started
}

// chRow is the on-the-wire shape ClickHouse expects for JSONEachRow:
// timestamps as `YYYY-MM-DD HH:MM:SS.ffffff` strings (CH parses both
// ISO8601 and this, but the latter is what queries return so we keep
// symmetry).
type chRow struct {
	TplID   string `json:"tpl_id"`
	TS      string `json:"ts"`
	Level   string `json:"level,omitempty"`
	Line    string `json:"line"`
	Attempt uint8  `json:"attempt"`
}

// Config wires the ClickHouse HTTP endpoint.
type Config struct {
	URL      string // e.g. "http://localhost:8123"
	Username string
	Password string
	Database string // default "createos"
	HTTP     *http.Client
}

// Client owns the connection details. Goroutine-safe; reuse one
// per process.
type Client struct {
	cfg Config
}

// New returns a Client. Schema must already exist — operators apply
// migrations out-of-band before deploying control.
func New(cfg Config) *Client {
	if cfg.Database == "" {
		cfg.Database = "createos"
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{cfg: cfg}
}

// Bootstrap is a no-op. ClickHouse schema is operator-managed via the
// standalone goose CLI — see `make migrate-ch-up` / `make migrate-ch-status`.
// The binary never embeds or runs migrations. Migration files live at
// internal/clickhouse/migrations_fs/*.sql as plain .sql for goose to read.
func (c *Client) Bootstrap(ctx context.Context) error { return nil }

// Append writes a batch of lines for one template, truncating oversized lines.
// The schema must already exist; Bootstrap does not create it.
func (c *Client) Append(ctx context.Context, tplID string, lines []Line) error {
	if len(lines) == 0 {
		return nil
	}
	now := time.Now().UTC()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for i := range lines {
		l := lines[i]
		if l.TS.IsZero() {
			l.TS = now
		}
		if l.Level == "" {
			l.Level = "info"
		}
		if len(l.Line) > MaxLineBytes {
			l.Line = l.Line[:MaxLineBytes-len("…[truncated]")] + "…[truncated]"
		}
		attempt := l.Attempt
		if attempt == 0 {
			attempt = 1
		}
		row := chRow{
			TplID:   tplID,
			TS:      l.TS.UTC().Format("2006-01-02 15:04:05.000000"),
			Level:   l.Level,
			Line:    l.Line,
			Attempt: attempt,
		}
		if err := enc.Encode(row); err != nil {
			return fmt.Errorf("encode line: %w", err)
		}
	}
	q := url.Values{}
	q.Set("query", "INSERT INTO "+c.cfg.Database+".build_logs (tpl_id, ts, level, line, attempt) FORMAT JSONEachRow")
	return c.post(ctx, q, &buf)
}

// GetAll returns lines for tpl_id ordered by attempt then timestamp, capped at limit.
// `attempt` filters to one specific build attempt; pass 0 for all
// attempts (mostly useful for forensic comparisons across retries).
func (c *Client) GetAll(ctx context.Context, tplID string, attempt uint8, limit int) ([]Line, error) {
	if limit <= 0 || limit > 100000 {
		limit = 100000
	}
	where := fmt.Sprintf("tpl_id = '%s'", escSQL(tplID))
	if attempt > 0 {
		where += fmt.Sprintf(" AND attempt = %d", attempt)
	}
	q := fmt.Sprintf(
		`SELECT tpl_id, toString(ts) AS ts, level, line, attempt FROM %s.build_logs WHERE %s ORDER BY attempt, ts LIMIT %d FORMAT JSONEachRow`,
		c.cfg.Database, where, limit,
	)
	body, err := c.query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return parseJSONEachRow(body)
}

// LatestAttempt returns the highest attempt number stored for this
// tpl_id (the most recent build). 0 if the row has no logs yet.
// Used by the reader endpoint when the user wants "current attempt".
func (c *Client) LatestAttempt(ctx context.Context, tplID string) (uint8, error) {
	q := fmt.Sprintf(
		`SELECT max(attempt) FROM %s.build_logs WHERE tpl_id = '%s' FORMAT TabSeparated`,
		c.cfg.Database, escSQL(tplID),
	)
	body, err := c.query(ctx, q)
	if err != nil {
		return 0, err
	}
	defer body.Close()
	var raw [16]byte
	n, _ := body.Read(raw[:])
	s := string(raw[:n])
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	if s == "" || s == "0" {
		return 0, nil
	}
	v, err := strconv.ParseUint(s, 10, 8)
	if err != nil {
		return 0, err
	}
	return uint8(v), nil
}

// Tail watches for new lines after `since` and emits them on `out`.
// Queries immediately, then polls every interval (default 1s). Returns on
// cancellation or query/parse error and does not close out. Each query returns
// at most 5000 rows strictly after the last observed timestamp.
func (c *Client) Tail(ctx context.Context, tplID string, since time.Time, interval time.Duration, out chan<- Line) error {
	if interval <= 0 {
		interval = time.Second
	}
	last := since
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		// Query everything strictly after `last`.
		q := fmt.Sprintf(
			`SELECT tpl_id, toString(ts) AS ts, level, line FROM %s.build_logs WHERE tpl_id = '%s' AND ts > toDateTime64('%s', 6) ORDER BY ts LIMIT 5000 FORMAT JSONEachRow`,
			c.cfg.Database, escSQL(tplID), last.UTC().Format("2006-01-02 15:04:05.000000"),
		)
		body, err := c.query(ctx, q)
		if err != nil {
			return err
		}
		lines, perr := parseJSONEachRow(body)
		body.Close()
		if perr != nil {
			return perr
		}
		for _, l := range lines {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case out <- l:
			}
			if l.TS.After(last) {
				last = l.TS
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// ── HTTP plumbing ──

func (c *Client) post(ctx context.Context, q url.Values, body io.Reader) error {
	u := c.cfg.URL + "?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	c.applyAuth(req)
	resp, err := c.cfg.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("clickhouse insert: HTTP %d: %s",
			resp.StatusCode, truncate(string(buf), 200))
	}
	return nil
}

func (c *Client) query(ctx context.Context, query string) (io.ReadCloser, error) {
	q := url.Values{}
	q.Set("query", query)
	u := c.cfg.URL + "?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	c.applyAuth(req)
	resp, err := c.cfg.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		return nil, fmt.Errorf("clickhouse query: HTTP %d: %s",
			resp.StatusCode, truncate(string(buf), 200))
	}
	return resp.Body, nil
}

func (c *Client) applyAuth(req *http.Request) {
	if c.cfg.Username != "" {
		req.SetBasicAuth(c.cfg.Username, c.cfg.Password)
	}
}

// ── helpers ──

func escSQL(s string) string {
	// build_logs.tpl_id is `tpl_<ulid>` — alphanumeric + underscore.
	// Strip all other bytes before embedding the ID in a quoted SQL literal.
	// This normalizes the input rather than returning a validation error;
	// the separately interpolated database name comes from trusted config.
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			out = append(out, c)
		}
	}
	return string(out)
}

func parseJSONEachRow(r io.Reader) ([]Line, error) {
	limited := &io.LimitedReader{R: r, N: MaxResponseBytes + 1}
	scanner := bufio.NewScanner(limited)
	// A line can expand sixfold in JSON. Allow metadata space as well.
	scanner.Buffer(make([]byte, 4096), MaxLineBytes*6+4096)
	var out []Line
	for scanner.Scan() {
		if limited.N == 0 {
			return nil, ErrResponseTooLarge
		}
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}
		var row struct {
			TplID   string `json:"tpl_id"`
			TS      string `json:"ts"`
			Level   string `json:"level"`
			Line    string `json:"line"`
			Attempt uint8  `json:"attempt"`
		}
		if err := json.Unmarshal(raw, &row); err != nil {
			continue
		}
		ts, err := time.Parse("2006-01-02 15:04:05.000000", row.TS)
		if err != nil {
			ts, _ = time.Parse(time.RFC3339Nano, row.TS)
		}
		out = append(out, Line{
			TplID:   row.TplID,
			TS:      ts.UTC(),
			Level:   row.Level,
			Line:    row.Line,
			Attempt: row.Attempt,
		})
	}
	if limited.N == 0 || errors.Is(scanner.Err(), bufio.ErrTooLong) {
		return nil, ErrResponseTooLarge
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ParseInt64Or returns the int64 form of s, or fallback on parse error.
// Exposed so tests/CLI can share the same digit handling.
func ParseInt64Or(s string, fallback int64) int64 {
	if s == "" {
		return fallback
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fallback
	}
	return n
}
