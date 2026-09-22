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
	if err != nil {
		return fmt.Errorf("migrate sqlite: %w", err)
	}
	return nil
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

func (s *Store) Close() error { return s.db.Close() }
