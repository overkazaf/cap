// Package sqlite implements store.Store on top of a pure-Go SQLite driver
// (modernc.org/sqlite — no CGo required). Flows are kept in a single table;
// map/slice fields are JSON-encoded into TEXT columns.
package sqlite

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver

	"github.com/nongjiawu/cap/internal/store"
	"github.com/nongjiawu/cap/internal/types"
)

var _ store.Store = (*SQLiteStore)(nil)

// ErrNotFound is returned (wrapped) by operations that reference a flow ID
// that does not exist in the store.
var ErrNotFound = errors.New("sqlite: flow not found")

// SQLiteStore is a store.Store backed by a single SQLite database file (or
// an in-memory database for tests).
type SQLiteStore struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS flows (
	id             TEXT PRIMARY KEY,
	timestamp      INTEGER NOT NULL,
	method         TEXT NOT NULL DEFAULT '',
	url            TEXT NOT NULL DEFAULT '',
	host           TEXT NOT NULL DEFAULT '',
	path           TEXT NOT NULL DEFAULT '',
	req_headers    TEXT NOT NULL DEFAULT '{}',
	req_body       BLOB,
	req_body_type  TEXT NOT NULL DEFAULT '',
	status         INTEGER NOT NULL DEFAULT 0,
	resp_headers   TEXT NOT NULL DEFAULT '{}',
	resp_body      BLOB,
	resp_body_type TEXT NOT NULL DEFAULT '',
	latency_ms     INTEGER NOT NULL DEFAULT 0,
	tags           TEXT NOT NULL DEFAULT '[]',
	sign_params    TEXT NOT NULL DEFAULT '[]',
	source_ref     TEXT
);
CREATE INDEX IF NOT EXISTS idx_flows_host   ON flows(host);
CREATE INDEX IF NOT EXISTS idx_flows_method ON flows(method);
CREATE INDEX IF NOT EXISTS idx_flows_status ON flows(status);
`

const flowColumns = `id, timestamp, method, url, host, path, req_headers, req_body, req_body_type,
	status, resp_headers, resp_body, resp_body_type, latency_ms, tags, sign_params, source_ref`

// New opens (creating if necessary) a SQLite-backed store at dsn. Pass
// ":memory:" for an ephemeral database (tests); pass a file path for
// persistent storage, e.g. "~/.cap/flows.db".
//
// The connection pool is capped at a single connection. modernc.org/sqlite
// gives each new connection to ":memory:" its own private, empty database,
// so pooling would silently "lose" previously saved rows; pinning to one
// connection also sidesteps SQLITE_BUSY without relying solely on
// busy_timeout for this single-process tool.
func New(dsn string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open %q: %w", dsn, err)
	}
	db.SetMaxOpenConns(1)

	if _, err := db.Exec("PRAGMA journal_mode = WAL;"); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: set journal_mode: %w", err)
	}
	if _, err := db.Exec("PRAGMA busy_timeout = 5000;"); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: set busy_timeout: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: create schema: %w", err)
	}

	return &SQLiteStore{db: db}, nil
}

// SaveFlow inserts f, or replaces the existing row with the same ID
// (upsert) — convenient for re-saving a flow after local mutation, since the
// store has no separate "UpdateFlow" method.
func (s *SQLiteStore) SaveFlow(f *types.Flow) error {
	if f == nil {
		return errors.New("sqlite: SaveFlow: flow is nil")
	}
	if f.ID == "" {
		return errors.New("sqlite: SaveFlow: flow ID is required")
	}

	reqHeaders, err := marshalJSON(f.ReqHeaders)
	if err != nil {
		return fmt.Errorf("sqlite: SaveFlow %q: encode req_headers: %w", f.ID, err)
	}
	respHeaders, err := marshalJSON(f.RespHeaders)
	if err != nil {
		return fmt.Errorf("sqlite: SaveFlow %q: encode resp_headers: %w", f.ID, err)
	}
	tags, err := marshalJSON(f.Tags)
	if err != nil {
		return fmt.Errorf("sqlite: SaveFlow %q: encode tags: %w", f.ID, err)
	}
	signParams, err := marshalJSON(f.SignParams)
	if err != nil {
		return fmt.Errorf("sqlite: SaveFlow %q: encode sign_params: %w", f.ID, err)
	}
	sourceRef, err := marshalSourceRef(f.SourceRef)
	if err != nil {
		return fmt.Errorf("sqlite: SaveFlow %q: encode source_ref: %w", f.ID, err)
	}

	const q = `INSERT INTO flows (` + flowColumns + `)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			timestamp = excluded.timestamp,
			method = excluded.method,
			url = excluded.url,
			host = excluded.host,
			path = excluded.path,
			req_headers = excluded.req_headers,
			req_body = excluded.req_body,
			req_body_type = excluded.req_body_type,
			status = excluded.status,
			resp_headers = excluded.resp_headers,
			resp_body = excluded.resp_body,
			resp_body_type = excluded.resp_body_type,
			latency_ms = excluded.latency_ms,
			tags = excluded.tags,
			sign_params = excluded.sign_params,
			source_ref = excluded.source_ref`

	_, err = s.db.Exec(q,
		f.ID, f.Timestamp.UnixNano(), f.Method, f.URL, f.Host, f.Path,
		reqHeaders, f.ReqBody, f.ReqBodyType,
		f.Status, respHeaders, f.RespBody, f.RespBodyType,
		f.LatencyMs, tags, signParams, sourceRef,
	)
	if err != nil {
		return fmt.Errorf("sqlite: SaveFlow %q: %w", f.ID, err)
	}
	return nil
}

// GetFlow returns the flow with the given ID, or an error wrapping
// ErrNotFound if it does not exist.
func (s *SQLiteStore) GetFlow(id string) (*types.Flow, error) {
	row := s.db.QueryRow(`SELECT `+flowColumns+` FROM flows WHERE id = ?`, id)
	f, err := scanFlow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("sqlite: GetFlow %q: %w", id, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: GetFlow %q: %w", id, err)
	}
	return f, nil
}

// ListFlows returns flows matching filter, newest first (by Timestamp).
//
// Host and Method match exactly; Path, Tag, and Search match as substrings
// (Tag matches against the flow's JSON-encoded tag array, so it cannot
// match across array entries). StatusFrom/StatusTo bound the status code
// inclusively and are ignored when <= 0. Limit/Offset paginate the ordered
// result set; Limit <= 0 means "no limit".
func (s *SQLiteStore) ListFlows(filter types.FlowFilter) ([]*types.Flow, error) {
	var where []string
	var args []any

	if filter.Host != "" {
		where = append(where, "host = ?")
		args = append(args, filter.Host)
	}
	if filter.Method != "" {
		where = append(where, "method = ?")
		args = append(args, filter.Method)
	}
	if filter.Path != "" {
		where = append(where, "path LIKE ?")
		args = append(args, likePattern(filter.Path))
	}
	if filter.StatusFrom > 0 {
		where = append(where, "status >= ?")
		args = append(args, filter.StatusFrom)
	}
	if filter.StatusTo > 0 {
		where = append(where, "status <= ?")
		args = append(args, filter.StatusTo)
	}
	if filter.Tag != "" {
		where = append(where, "tags LIKE ?")
		args = append(args, `%"`+filter.Tag+`"%`)
	}
	if filter.Search != "" {
		where = append(where, "(url LIKE ? OR CAST(req_body AS TEXT) LIKE ?)")
		p := likePattern(filter.Search)
		args = append(args, p, p)
	}

	var q strings.Builder
	q.WriteString("SELECT ")
	q.WriteString(flowColumns)
	q.WriteString(" FROM flows")
	if len(where) > 0 {
		q.WriteString(" WHERE ")
		q.WriteString(strings.Join(where, " AND "))
	}
	q.WriteString(" ORDER BY timestamp DESC")

	if filter.Limit > 0 {
		q.WriteString(" LIMIT ?")
		args = append(args, filter.Limit)
		if filter.Offset > 0 {
			q.WriteString(" OFFSET ?")
			args = append(args, filter.Offset)
		}
	} else if filter.Offset > 0 {
		// SQLite requires a LIMIT clause before OFFSET; -1 means unbounded.
		q.WriteString(" LIMIT -1 OFFSET ?")
		args = append(args, filter.Offset)
	}

	rows, err := s.db.Query(q.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: ListFlows: %w", err)
	}
	defer rows.Close()

	flows := make([]*types.Flow, 0)
	for rows.Next() {
		f, err := scanFlow(rows)
		if err != nil {
			return nil, fmt.Errorf("sqlite: ListFlows: scan: %w", err)
		}
		flows = append(flows, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: ListFlows: %w", err)
	}
	return flows, nil
}

// DeleteFlow removes the flow with the given ID. Deleting a non-existent ID
// is not an error.
func (s *SQLiteStore) DeleteFlow(id string) error {
	if _, err := s.db.Exec("DELETE FROM flows WHERE id = ?", id); err != nil {
		return fmt.Errorf("sqlite: DeleteFlow %q: %w", id, err)
	}
	return nil
}

// UpdateTags replaces the tag set of the flow with the given ID.
func (s *SQLiteStore) UpdateTags(id string, tags []string) error {
	b, err := marshalJSON(tags)
	if err != nil {
		return fmt.Errorf("sqlite: UpdateTags %q: encode tags: %w", id, err)
	}
	res, err := s.db.Exec("UPDATE flows SET tags = ? WHERE id = ?", b, id)
	if err != nil {
		return fmt.Errorf("sqlite: UpdateTags %q: %w", id, err)
	}
	return requireRowUpdated(res, id)
}

// UpdateSourceRef sets (or clears, if ref is nil) the source-code reference
// for the flow with the given ID.
func (s *SQLiteStore) UpdateSourceRef(id string, ref *types.SourceRef) error {
	v, err := marshalSourceRef(ref)
	if err != nil {
		return fmt.Errorf("sqlite: UpdateSourceRef %q: encode source_ref: %w", id, err)
	}
	res, err := s.db.Exec("UPDATE flows SET source_ref = ? WHERE id = ?", v, id)
	if err != nil {
		return fmt.Errorf("sqlite: UpdateSourceRef %q: %w", id, err)
	}
	return requireRowUpdated(res, id)
}

// Close releases the underlying database handle.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// requireRowUpdated turns a successful but no-op UPDATE (unknown id) into an
// ErrNotFound. Drivers that can't report RowsAffected are tolerated: we only
// escalate when the driver positively confirms zero rows changed.
func requireRowUpdated(res sql.Result, id string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return nil
	}
	if n == 0 {
		return fmt.Errorf("sqlite: %q: %w", id, ErrNotFound)
	}
	return nil
}

// likePattern wraps s for a substring LIKE match, escaping SQLite's LIKE
// wildcards so literal '%' and '_' in user-supplied filter values (e.g. a
// path or search term) aren't misinterpreted.
func likePattern(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(s) + "%"
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows, letting GetFlow
// and ListFlows share one scan routine.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanFlow(row rowScanner) (*types.Flow, error) {
	var f types.Flow
	var tsNano int64
	var reqHeaders, respHeaders, tags, signParams string
	var sourceRef sql.NullString

	err := row.Scan(
		&f.ID, &tsNano, &f.Method, &f.URL, &f.Host, &f.Path,
		&reqHeaders, &f.ReqBody, &f.ReqBodyType,
		&f.Status, &respHeaders, &f.RespBody, &f.RespBodyType,
		&f.LatencyMs, &tags, &signParams, &sourceRef,
	)
	if err != nil {
		return nil, err
	}

	f.Timestamp = time.Unix(0, tsNano).UTC()

	if err := unmarshalJSON(reqHeaders, &f.ReqHeaders); err != nil {
		return nil, fmt.Errorf("decode req_headers: %w", err)
	}
	if err := unmarshalJSON(respHeaders, &f.RespHeaders); err != nil {
		return nil, fmt.Errorf("decode resp_headers: %w", err)
	}
	if err := unmarshalJSON(tags, &f.Tags); err != nil {
		return nil, fmt.Errorf("decode tags: %w", err)
	}
	if err := unmarshalJSON(signParams, &f.SignParams); err != nil {
		return nil, fmt.Errorf("decode sign_params: %w", err)
	}
	if sourceRef.Valid {
		ref, err := unmarshalSourceRef(sourceRef.String)
		if err != nil {
			return nil, fmt.Errorf("decode source_ref: %w", err)
		}
		f.SourceRef = ref
	}

	return &f, nil
}
