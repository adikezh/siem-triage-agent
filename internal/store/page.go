package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrPageConflict means another writer has already committed this page or one
// of its alerts. The caller must reload its checkpoint and prepare a new page.
var ErrPageConflict = errors.New("ingest page changed before commit")

type AlertWrite struct {
	ID, Source string
	Timestamp  time.Time
	Payload    any
}

type IncidentWrite struct {
	ID, Fingerprint, Severity string
	Score, Count              int
	FirstSeen, LastSeen       time.Time
	Payload                   any
}

type NotificationWrite struct {
	IncidentID, Channel string
	Payload             []byte
}

// Page is prepared without holding a database transaction (in particular,
// enrichment and model requests never lock the UI out of SQLite).
type Page struct {
	Alerts        []AlertWrite
	Incidents     []IncidentWrite
	Traces        []LLMTrace
	Notifications []NotificationWrite
}

func (s *Store) ExistingAlertIDs(ctx context.Context, ids []string) (map[string]bool, error) {
	out := make(map[string]bool)
	// Stay below SQLite's bind-parameter limit even for large source pages.
	for start := 0; start < len(ids); start += 500 {
		end := min(start+500, len(ids))
		args := make([]any, end-start)
		for i, id := range ids[start:end] {
			args[i] = id
		}
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")
		rows, err := s.db.QueryContext(ctx, `SELECT id FROM alerts WHERE id IN (`+placeholders+`)`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, err
			}
			out[id] = true
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// CommitPage atomically persists all effects of a page and its checkpoint.
// Neither a crash nor a failed outbox write can advance past unsaved work.
func (s *Store) CommitPage(ctx context.Context, source string, expected, next Cursor, page Page) error {
	if source == "" || next.Timestamp.Before(expected.Timestamp) || !json.Valid(next.SortJSON) {
		return fmt.Errorf("invalid ingest checkpoint")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var timestamp string
	var sortJSON []byte
	err = tx.QueryRowContext(ctx, `SELECT timestamp,sort_json FROM source_cursors WHERE source=?`, source).Scan(&timestamp, &sortJSON)
	var current Cursor
	if err == nil {
		current.Timestamp, err = time.Parse(time.RFC3339Nano, timestamp)
		current.SortJSON = sortJSON
	} else if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	if err != nil {
		return err
	}
	if !current.Timestamp.Equal(expected.Timestamp) || !bytes.Equal(current.SortJSON, expected.SortJSON) {
		return ErrPageConflict
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, a := range page.Alerts {
		if a.ID == "" || a.Source == "" || a.Timestamp.IsZero() {
			return fmt.Errorf("invalid alert identity")
		}
		payload, err := json.Marshal(a.Payload)
		if err != nil {
			return fmt.Errorf("encode alert: %w", err)
		}
		result, err := tx.ExecContext(ctx, `INSERT INTO alerts(id,source,timestamp,payload) VALUES(?,?,?,?) ON CONFLICT(id) DO NOTHING`, a.ID, a.Source, a.Timestamp.UTC().Format(time.RFC3339Nano), payload)
		if err != nil {
			return fmt.Errorf("save alert: %w", err)
		}
		inserted, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if inserted != 1 {
			return ErrPageConflict
		}
	}
	for _, i := range page.Incidents {
		payload, err := json.Marshal(i.Payload)
		if err != nil {
			return fmt.Errorf("encode incident: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO incidents(id,fingerprint,first_seen,last_seen,alert_count,score,severity,payload) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen,alert_count=excluded.alert_count,score=excluded.score,severity=excluded.severity,payload=excluded.payload`, i.ID, i.Fingerprint, i.FirstSeen.UTC().Format(time.RFC3339Nano), i.LastSeen.UTC().Format(time.RFC3339Nano), i.Count, i.Score, i.Severity, payload); err != nil {
			return fmt.Errorf("save incident: %w", err)
		}
	}
	for _, t := range page.Traces {
		if _, err := tx.ExecContext(ctx, `INSERT INTO llm_calls(incident_id,provider,model,prompt_hash,latency_ms,used,error,created_at) VALUES(?,?,?,?,?,?,?,?)`, t.IncidentID, t.Provider, t.Model, t.PromptHash, t.LatencyMS, t.Used, t.Error, now); err != nil {
			return fmt.Errorf("save model trace: %w", err)
		}
	}
	for _, n := range page.Notifications {
		if n.IncidentID == "" || n.Channel == "" {
			return fmt.Errorf("invalid notification identity")
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO outbox(incident_id,channel,payload,next_attempt_at,created_at) VALUES(?,?,?,?,?) ON CONFLICT(incident_id,channel) DO NOTHING`, n.IncidentID, n.Channel, n.Payload, now, now); err != nil {
			return fmt.Errorf("enqueue notification: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO source_cursors(source,timestamp,sort_json,updated_at) VALUES(?,?,?,?) ON CONFLICT(source) DO UPDATE SET timestamp=excluded.timestamp,sort_json=excluded.sort_json,updated_at=excluded.updated_at`, source, next.Timestamp.UTC().Format(time.RFC3339Nano), next.SortJSON, now); err != nil {
		return fmt.Errorf("save checkpoint: %w", err)
	}
	return tx.Commit()
}
