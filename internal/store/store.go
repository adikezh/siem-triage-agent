package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }

type Record struct {
	ID, Fingerprint, FirstSeen, LastSeen, Severity string
	AlertCount, Score                              int
	Payload                                        json.RawMessage
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, source TEXT NOT NULL, timestamp TEXT NOT NULL, payload BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, alert_count INTEGER NOT NULL, score INTEGER NOT NULL, severity TEXT NOT NULL, payload BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS feedback (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL REFERENCES incidents(id), verdict TEXT NOT NULL CHECK(verdict IN ('tp','fp','ack')), comment TEXT NOT NULL DEFAULT '', actor TEXT NOT NULL, created_at TEXT NOT NULL);
	CREATE TABLE IF NOT EXISTS suppressions (id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT NOT NULL, action TEXT NOT NULL CHECK(action IN ('drop','downgrade','tag')), reason TEXT NOT NULL, expires_at TEXT, created_by TEXT NOT NULL, created_at TEXT NOT NULL);`)
	_, err = s.db.Exec(`CREATE TABLE IF NOT EXISTS llm_calls (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL, provider TEXT NOT NULL, model TEXT NOT NULL, prompt_hash TEXT NOT NULL, latency_ms INTEGER NOT NULL, used INTEGER NOT NULL, error TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL)`)
	_, err = s.db.Exec(`CREATE TABLE IF NOT EXISTS source_cursors (source TEXT PRIMARY KEY, timestamp TEXT NOT NULL, sort_json BLOB NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS outbox (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL, channel TEXT NOT NULL, payload BLOB NOT NULL, status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT NOT NULL, last_error TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, UNIQUE(incident_id,channel));`)
	if err != nil {
		return fmt.Errorf("migrate sqlite: %w", err)
	}
	return nil
}

type LLMTrace struct {
	IncidentID, Provider, Model, PromptHash, Error string
	LatencyMS                                      int64
	Used                                           bool
}

type Cursor struct {
	Timestamp time.Time
	SortJSON  []byte
}

func (s *Store) LoadCursor(ctx context.Context, source string) (Cursor, error) {
	var c Cursor
	var ts string
	err := s.db.QueryRowContext(ctx, `SELECT timestamp,sort_json FROM source_cursors WHERE source=?`, source).Scan(&ts, &c.SortJSON)
	if err == sql.ErrNoRows {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	c.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
	return c, nil
}
func (s *Store) SaveCursor(ctx context.Context, source string, c Cursor) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO source_cursors(source,timestamp,sort_json,updated_at) VALUES(?,?,?,?) ON CONFLICT(source) DO UPDATE SET timestamp=excluded.timestamp,sort_json=excluded.sort_json,updated_at=excluded.updated_at`, source, c.Timestamp.UTC().Format(time.RFC3339Nano), c.SortJSON, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

type OutboxItem struct {
	ID                  int64
	IncidentID, Channel string
	Payload             []byte
	Attempts            int
	Status              string
	NextAttemptAt       time.Time
	LastError           string
}

func (s *Store) Enqueue(ctx context.Context, incidentID, channel string, payload []byte) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO outbox(incident_id,channel,payload,next_attempt_at,created_at) VALUES(?,?,?, ?,?) ON CONFLICT(incident_id,channel) DO NOTHING`, incidentID, channel, payload, time.Now().UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}
func (s *Store) PendingOutbox(ctx context.Context, limit int) ([]OutboxItem, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, e := s.db.QueryContext(ctx, `SELECT id,incident_id,channel,payload,status,attempts,next_attempt_at,last_error FROM outbox WHERE status='pending' AND next_attempt_at<=? ORDER BY id LIMIT ?`, time.Now().UTC().Format(time.RFC3339Nano), limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []OutboxItem
	for rows.Next() {
		var x OutboxItem
		var ts string
		if e = rows.Scan(&x.ID, &x.IncidentID, &x.Channel, &x.Payload, &x.Status, &x.Attempts, &ts, &x.LastError); e != nil {
			return nil, e
		}
		x.NextAttemptAt, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, x)
	}
	return out, rows.Err()
}
func (s *Store) MarkOutbox(ctx context.Context, id int64, success bool, next time.Time, lastError string) error {
	status := "pending"
	if success {
		status = "sent"
	}
	_, err := s.db.ExecContext(ctx, `UPDATE outbox SET status=?,attempts=attempts+1,next_attempt_at=?,last_error=? WHERE id=?`, status, next.UTC().Format(time.RFC3339Nano), lastError, id)
	return err
}

func (s *Store) SaveLLMTrace(ctx context.Context, t LLMTrace) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO llm_calls(incident_id,provider,model,prompt_hash,latency_ms,used,error,created_at) VALUES(?,?,?,?,?,?,?,?)`, t.IncidentID, t.Provider, t.Model, t.PromptHash, t.LatencyMS, t.Used, t.Error, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) SaveIncident(ctx context.Context, incident any, id, fingerprint, severity string, score, count int, first, last time.Time) error {
	payload, err := json.Marshal(incident)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO incidents(id,fingerprint,first_seen,last_seen,alert_count,score,severity,payload) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen,alert_count=excluded.alert_count,score=excluded.score,severity=excluded.severity,payload=excluded.payload`, id, fingerprint, first.UTC().Format(time.RFC3339Nano), last.UTC().Format(time.RFC3339Nano), count, score, severity, payload)
	return err
}

func (s *Store) AddFeedback(ctx context.Context, incidentID, verdict, comment, actor string) error {
	if actor == "" {
		actor = "anonymous"
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO feedback(incident_id,verdict,comment,actor,created_at) VALUES(?,?,?,?,?)`, incidentID, verdict, comment, actor, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) ListIncidents(ctx context.Context) ([]Record, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,fingerprint,first_seen,last_seen,alert_count,score,severity,payload FROM incidents ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var r Record
		if err := rows.Scan(&r.ID, &r.Fingerprint, &r.FirstSeen, &r.LastSeen, &r.AlertCount, &r.Score, &r.Severity, &r.Payload); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetIncident(ctx context.Context, id string) (Record, error) {
	var r Record
	var p []byte
	err := s.db.QueryRowContext(ctx, `SELECT id,fingerprint,first_seen,last_seen,alert_count,score,severity,payload FROM incidents WHERE id=?`, id).Scan(&r.ID, &r.Fingerprint, &r.FirstSeen, &r.LastSeen, &r.AlertCount, &r.Score, &r.Severity, &p)
	r.Payload = p
	return r, err
}

func (s *Store) Close() error { return s.db.Close() }
