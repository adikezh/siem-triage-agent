package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }

type AuditRecord struct {
	ID                                               int64 `json:"id"`
	Event, Actor, Payload, PrevHash, Hash, CreatedAt string
}

type Record struct {
	ID, Fingerprint, FirstSeen, LastSeen, Severity string
	AlertCount, Score                              int
	Payload                                        json.RawMessage
}

type SuppressionRecord struct {
	ID          int64  `json:"id"`
	Fingerprint string `json:"fingerprint"`
	Action      string `json:"action"`
	Reason      string `json:"reason"`
	ExpiresAt   string `json:"expires_at,omitempty"`
	CreatedBy   string `json:"created_by"`
	CreatedAt   string `json:"created_at"`
}

type ThreatCacheRecord struct {
	IP, Source, Details, ExpiresAt string
	Malicious                      bool
}

type HistoryRecord struct {
	IncidentID, Severity, Verdict, LastSeen string
}

type APIKeyRecord struct {
	ID                          int64
	Name, Role, Hash, CreatedAt string
}

type APIKeyInfo struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	CreatedAt string `json:"created_at"`
	RevokedAt string `json:"revoked_at,omitempty"`
}

func (s *Store) SaveAlert(ctx context.Context, id, source string, timestamp time.Time, payload any) error {
	b, e := json.Marshal(payload)
	if e != nil {
		return e
	}
	_, e = s.db.ExecContext(ctx, `INSERT INTO alerts(id,source,timestamp,payload) VALUES(?,?,?,?) ON CONFLICT(id) DO NOTHING`, id, source, timestamp.UTC().Format(time.RFC3339Nano), b)
	return e
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
	exec := func(query string) error { _, err := s.db.Exec(query); return err }
	if err := exec(`CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, source TEXT NOT NULL, timestamp TEXT NOT NULL, payload BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, alert_count INTEGER NOT NULL, score INTEGER NOT NULL, severity TEXT NOT NULL, payload BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS feedback (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL REFERENCES incidents(id), verdict TEXT NOT NULL CHECK(verdict IN ('tp','fp','ack')), comment TEXT NOT NULL DEFAULT '', actor TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS suppressions (id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT NOT NULL, action TEXT NOT NULL CHECK(action IN ('drop','downgrade','tag')), reason TEXT NOT NULL, expires_at TEXT, created_by TEXT NOT NULL, created_at TEXT NOT NULL);`); err != nil {
		return fmt.Errorf("migrate sqlite: %w", err)
	}
	for _, query := range []string{`CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL, actor TEXT NOT NULL, payload TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL)`, `CREATE TABLE IF NOT EXISTS llm_calls (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL, provider TEXT NOT NULL, model TEXT NOT NULL, prompt_hash TEXT NOT NULL, latency_ms INTEGER NOT NULL, used INTEGER NOT NULL, error TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL)`, `CREATE TABLE IF NOT EXISTS source_cursors (source TEXT PRIMARY KEY, timestamp TEXT NOT NULL, sort_json BLOB NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS outbox (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL, channel TEXT NOT NULL, payload BLOB NOT NULL, status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT NOT NULL, last_error TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, UNIQUE(incident_id,channel));`} {
		if err := exec(query); err != nil {
			return fmt.Errorf("migrate sqlite: %w", err)
		}
	}
	if err := exec(`CREATE TABLE IF NOT EXISTS threat_cache (ip TEXT PRIMARY KEY, source TEXT NOT NULL, details TEXT NOT NULL, malicious INTEGER NOT NULL, expires_at TEXT NOT NULL, updated_at TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("migrate sqlite: %w", err)
	}
	return exec(`CREATE TABLE IF NOT EXISTS api_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, role TEXT NOT NULL CHECK(role IN ('viewer','analyst','admin')), key_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, revoked_at TEXT)`)
}

func HashAPIKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (s *Store) CreateAPIKey(ctx context.Context, name, role, raw string) (APIKeyRecord, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	r, err := s.db.ExecContext(ctx, `INSERT INTO api_keys(name,role,key_hash,created_at) VALUES(?,?,?,?)`, name, role, HashAPIKey(raw), now)
	if err != nil {
		return APIKeyRecord{}, err
	}
	id, err := r.LastInsertId()
	if err != nil {
		return APIKeyRecord{}, err
	}
	return APIKeyRecord{ID: id, Name: name, Role: role, Hash: HashAPIKey(raw), CreatedAt: now}, nil
}

func (s *Store) HasAPIKeys(ctx context.Context) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_keys WHERE revoked_at IS NULL`).Scan(&n)
	return n > 0, err
}
func (s *Store) VerifyAPIKey(ctx context.Context, raw string) (string, bool, error) {
	var role string
	err := s.db.QueryRowContext(ctx, `SELECT role FROM api_keys WHERE key_hash=? AND revoked_at IS NULL`, HashAPIKey(raw)).Scan(&role)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return role, true, nil
}

func (s *Store) RevokeAPIKey(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE api_keys SET revoked_at=? WHERE id=? AND revoked_at IS NULL`, time.Now().UTC().Format(time.RFC3339Nano), id)
	return err
}

func (s *Store) ListAPIKeys(ctx context.Context) ([]APIKeyInfo, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,role,created_at,COALESCE(revoked_at,'') FROM api_keys ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIKeyInfo
	for rows.Next() {
		var x APIKeyInfo
		if err := rows.Scan(&x.ID, &x.Name, &x.Role, &x.CreatedAt, &x.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (s *Store) LoadThreatCache(ctx context.Context, ip string, now time.Time) (ThreatCacheRecord, bool, error) {
	var x ThreatCacheRecord
	var malicious int
	err := s.db.QueryRowContext(ctx, `SELECT ip,source,details,malicious,expires_at FROM threat_cache WHERE ip=? AND expires_at>?`, ip, now.UTC().Format(time.RFC3339Nano)).Scan(&x.IP, &x.Source, &x.Details, &malicious, &x.ExpiresAt)
	if err == sql.ErrNoRows {
		return ThreatCacheRecord{}, false, nil
	}
	if err != nil {
		return ThreatCacheRecord{}, false, err
	}
	x.Malicious = malicious != 0
	return x, true, nil
}

func (s *Store) SaveThreatCache(ctx context.Context, x ThreatCacheRecord, ttl time.Duration) error {
	now := time.Now().UTC()
	expires := now.Add(ttl).Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `INSERT INTO threat_cache(ip,source,details,malicious,expires_at,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET source=excluded.source,details=excluded.details,malicious=excluded.malicious,expires_at=excluded.expires_at,updated_at=excluded.updated_at`, x.IP, x.Source, x.Details, x.Malicious, expires, now.Format(time.RFC3339Nano))
	return err
}

type LLMTrace struct {
	IncidentID, Provider, Model, PromptHash, Error string
	LatencyMS                                      int64
	Used                                           bool
}

type MetricsSnapshot struct {
	LLMCalls, LLMUsed, LLMErrors        int
	LLMLatencyMS                        float64
	FeedbackTP, FeedbackFP, FeedbackAck int
	OutboxPending, OutboxSent           int
}

func (s *Store) Metrics(ctx context.Context) (MetricsSnapshot, error) {
	var m MetricsSnapshot
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(CASE WHEN used=1 THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN error<>'' THEN 1 ELSE 0 END),0),COALESCE(AVG(CASE WHEN used=1 THEN latency_ms END),0) FROM llm_calls`).Scan(&m.LLMCalls, &m.LLMUsed, &m.LLMErrors, &m.LLMLatencyMS); err != nil {
		return m, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT verdict,COUNT(*) FROM feedback GROUP BY verdict`)
	if err != nil {
		return m, err
	}
	defer rows.Close()
	for rows.Next() {
		var verdict string
		var count int
		if err := rows.Scan(&verdict, &count); err != nil {
			return m, err
		}
		switch verdict {
		case "tp":
			m.FeedbackTP = count
		case "fp":
			m.FeedbackFP = count
		case "ack":
			m.FeedbackAck = count
		}
	}
	if err := rows.Err(); err != nil {
		return m, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN status='sent' THEN 1 ELSE 0 END),0) FROM outbox`).Scan(&m.OutboxPending, &m.OutboxSent); err != nil {
		return m, err
	}
	return m, nil
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

func (s *Store) ListLLMTraces(ctx context.Context) ([]LLMTrace, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT incident_id,provider,model,prompt_hash,latency_ms,used,error FROM llm_calls ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LLMTrace
	for rows.Next() {
		var t LLMTrace
		if err := rows.Scan(&t.IncidentID, &t.Provider, &t.Model, &t.PromptHash, &t.LatencyMS, &t.Used, &t.Error); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) Prune(ctx context.Context, alertBefore, llmBefore time.Time) error {
	if !alertBefore.IsZero() {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM alerts WHERE timestamp<?`, alertBefore.UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	if !llmBefore.IsZero() {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM llm_calls WHERE created_at<?`, llmBefore.UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
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
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `INSERT INTO feedback(incident_id,verdict,comment,actor,created_at) VALUES(?,?,?,?,?)`, incidentID, verdict, comment, actor, now)
	if err != nil {
		return err
	}
	return s.appendAudit(ctx, "feedback.added", actor, map[string]string{"incident_id": incidentID, "verdict": verdict, "comment": comment})
}

func (s *Store) CreateSuppression(ctx context.Context, fingerprint, action, reason, expiresAt, createdBy string) (SuppressionRecord, error) {
	if createdBy == "" {
		createdBy = "api"
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	r, err := s.db.ExecContext(ctx, `INSERT INTO suppressions(fingerprint,action,reason,expires_at,created_by,created_at) VALUES(?,?,?,?,?,?)`, fingerprint, action, reason, nullableText(expiresAt), createdBy, now)
	if err != nil {
		return SuppressionRecord{}, err
	}
	id, err := r.LastInsertId()
	if err != nil {
		return SuppressionRecord{}, err
	}
	if err = s.appendAudit(ctx, "suppression.created", createdBy, SuppressionRecord{ID: id, Fingerprint: fingerprint, Action: action, Reason: reason, ExpiresAt: expiresAt, CreatedBy: createdBy, CreatedAt: now}); err != nil {
		return SuppressionRecord{}, err
	}
	return SuppressionRecord{ID: id, Fingerprint: fingerprint, Action: action, Reason: reason, ExpiresAt: expiresAt, CreatedBy: createdBy, CreatedAt: now}, nil
}

func (s *Store) ListSuppressions(ctx context.Context) ([]SuppressionRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,fingerprint,action,reason,COALESCE(expires_at,''),created_by,created_at FROM suppressions ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SuppressionRecord
	for rows.Next() {
		var x SuppressionRecord
		if err := rows.Scan(&x.ID, &x.Fingerprint, &x.Action, &x.Reason, &x.ExpiresAt, &x.CreatedBy, &x.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (s *Store) DeleteSuppression(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM suppressions WHERE id=?`, id)
	if err != nil {
		return err
	}
	return s.appendAudit(ctx, "suppression.deleted", "api", map[string]any{"id": id})
}

func (s *Store) appendAudit(ctx context.Context, event, actor string, payload any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	var prev string
	if err = s.db.QueryRowContext(ctx, `SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&prev); err == sql.ErrNoRows {
		err = nil
	}
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	sum := sha256.Sum256([]byte(prev + "\n" + event + "\n" + actor + "\n" + string(b) + "\n" + now))
	hash := hex.EncodeToString(sum[:])
	_, err = s.db.ExecContext(ctx, `INSERT INTO audit_log(event,actor,payload,prev_hash,hash,created_at) VALUES(?,?,?,?,?,?)`, event, actor, string(b), prev, hash, now)
	return err
}

func (s *Store) VerifyAuditChain(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT event,actor,payload,prev_hash,hash,created_at FROM audit_log ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	prev := ""
	for rows.Next() {
		var event, actor, payload, storedPrev, storedHash, createdAt string
		if err = rows.Scan(&event, &actor, &payload, &storedPrev, &storedHash, &createdAt); err != nil {
			return err
		}
		if storedPrev != prev {
			return fmt.Errorf("audit chain broken: previous hash mismatch")
		}
		sum := sha256.Sum256([]byte(prev + "\n" + event + "\n" + actor + "\n" + payload + "\n" + createdAt))
		if hex.EncodeToString(sum[:]) != storedHash {
			return fmt.Errorf("audit chain broken: hash mismatch")
		}
		prev = storedHash
	}
	return rows.Err()
}

func nullableText(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func (s *Store) ListIncidents(ctx context.Context) ([]Record, error) {
	return s.ListIncidentsFiltered(ctx, "", "", 0)
}

func (s *Store) ListIncidentsFiltered(ctx context.Context, severity, since string, limit int) ([]Record, error) {
	query := `SELECT id,fingerprint,first_seen,last_seen,alert_count,score,severity,payload FROM incidents`
	where := []string{}
	args := []any{}
	if severity != "" {
		where = append(where, "severity=?")
		args = append(args, severity)
	}
	if since != "" {
		where = append(where, "last_seen>=?")
		args = append(args, since)
	}
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY last_seen DESC"
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
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

func (s *Store) LatestIncidentByFingerprint(ctx context.Context, fingerprint string) (Record, error) {
	var r Record
	var p []byte
	err := s.db.QueryRowContext(ctx, `SELECT id,fingerprint,first_seen,last_seen,alert_count,score,severity,payload FROM incidents WHERE fingerprint=? ORDER BY last_seen DESC LIMIT 1`, fingerprint).Scan(&r.ID, &r.Fingerprint, &r.FirstSeen, &r.LastSeen, &r.AlertCount, &r.Score, &r.Severity, &p)
	r.Payload = p
	return r, err
}

func (s *Store) FalsePositiveCount(ctx context.Context, fingerprint string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM feedback f JOIN incidents i ON i.id=f.incident_id WHERE i.fingerprint=? AND f.verdict='fp'`, fingerprint).Scan(&n)
	return n, err
}

// FingerprintStats returns the number of alerts represented by incidents seen
// since the supplied time and whether analysts have ever marked that
// fingerprint as a true positive.
func (s *Store) FingerprintStats(ctx context.Context, fingerprint string, since time.Time) (count int, hasTP bool, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(alert_count),0) FROM incidents WHERE fingerprint=? AND last_seen>=?`, fingerprint, since.UTC().Format(time.RFC3339Nano)).Scan(&count)
	if err != nil {
		return 0, false, err
	}
	err = s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM feedback f JOIN incidents i ON i.id=f.incident_id WHERE i.fingerprint=? AND f.verdict='tp')`, fingerprint).Scan(&hasTP)
	return count, hasTP, err
}

func (s *Store) IncidentHistory(ctx context.Context, fingerprint string, limit int) ([]HistoryRecord, error) {
	if limit <= 0 {
		limit = 5
	}
	rows, err := s.db.QueryContext(ctx, `SELECT i.id,i.severity,COALESCE((SELECT f.verdict FROM feedback f WHERE f.incident_id=i.id ORDER BY f.id DESC LIMIT 1),''),i.last_seen FROM incidents i WHERE i.fingerprint=? ORDER BY i.last_seen DESC LIMIT ?`, fingerprint, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HistoryRecord
	for rows.Next() {
		var x HistoryRecord
		if err := rows.Scan(&x.IncidentID, &x.Severity, &x.Verdict, &x.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

type FeedbackRecord struct {
	IncidentID, Verdict, Comment, Actor, CreatedAt string
	Payload                                        json.RawMessage
}

func (s *Store) ListFeedback(ctx context.Context) ([]FeedbackRecord, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT f.incident_id,f.verdict,f.comment,f.actor,f.created_at,i.payload FROM feedback f LEFT JOIN incidents i ON i.id=f.incident_id ORDER BY f.id`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []FeedbackRecord
	for rows.Next() {
		var x FeedbackRecord
		if e = rows.Scan(&x.IncidentID, &x.Verdict, &x.Comment, &x.Actor, &x.CreatedAt, &x.Payload); e != nil {
			return nil, e
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (s *Store) Close() error { return s.db.Close() }
