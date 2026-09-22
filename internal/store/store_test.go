package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLitePersistenceAndFeedback(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "triage.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	now := time.Now()
	if e = s.SaveIncident(context.Background(), map[string]string{"x": "y"}, "i1", "r|a|ip", "medium", 50, 2, now, now); e != nil {
		t.Fatal(e)
	}
	if e = s.SaveAlert(context.Background(), "a1", "file", now, map[string]string{"rule": "r"}); e != nil {
		t.Fatal(e)
	}
	if e = s.SaveAlert(context.Background(), "a1", "file", now, map[string]string{"rule": "changed"}); e != nil {
		t.Fatal(e)
	}
	if e = s.AddFeedback(context.Background(), "i1", "fp", "noise", "analyst"); e != nil {
		t.Fatal(e)
	}
	if e = s.SaveLLMTrace(context.Background(), LLMTrace{IncidentID: "i1", Provider: "rule-only", Model: "", PromptHash: "abc"}); e != nil {
		t.Fatal(e)
	}
	if e = s.SaveCursor(context.Background(), "wazuh", Cursor{Timestamp: now, SortJSON: []byte(`["x"]`)}); e != nil {
		t.Fatal(e)
	}
	c, _ := s.LoadCursor(context.Background(), "wazuh")
	if c.Timestamp.IsZero() {
		t.Fatal("cursor not persisted")
	}
	if e = s.Enqueue(context.Background(), "i1", "webhook", []byte(`{"x":1}`)); e != nil {
		t.Fatal(e)
	}
	items, e := s.PendingOutbox(context.Background(), 10)
	if e != nil || len(items) != 1 {
		t.Fatalf("outbox %#v %v", items, e)
	}
	if e = s.MarkOutbox(context.Background(), items[0].ID, true, time.Now().Add(time.Hour), ""); e != nil {
		t.Fatal(e)
	}
	if n, e := s.FalsePositiveCount(context.Background(), "r|a|ip"); e != nil || n != 1 {
		t.Fatalf("fp count=%d %v", n, e)
	}
	if rows, e := s.ListFeedback(context.Background()); e != nil || len(rows) != 1 || rows[0].Verdict != "fp" {
		t.Fatalf("feedback=%#v %v", rows, e)
	}
	if e = s.VerifyAuditChain(context.Background()); e != nil {
		t.Fatal(e)
	}
}

func TestSuppressionCRUD(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "triage.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	x, err := s.CreateSuppression(context.Background(), "r|a|10.0.0.1", "drop", "known scanner", "", "analyst")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListSuppressions(context.Background())
	if err != nil || len(rows) != 1 || rows[0].ID != x.ID || rows[0].Action != "drop" {
		t.Fatalf("rows=%#v err=%v", rows, err)
	}
	if err = s.DeleteSuppression(context.Background(), x.ID); err != nil {
		t.Fatal(err)
	}
	rows, err = s.ListSuppressions(context.Background())
	if err != nil || len(rows) != 0 {
		t.Fatalf("rows after delete=%#v err=%v", rows, err)
	}
	if err = s.VerifyAuditChain(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestThreatCachePersistence(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "triage.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.SaveThreatCache(context.Background(), ThreatCacheRecord{IP: "1.2.3.4", Source: "test", Details: "score=90", Malicious: true}, time.Hour); err != nil {
		t.Fatal(err)
	}
	x, ok, err := s.LoadThreatCache(context.Background(), "1.2.3.4", time.Now())
	if err != nil || !ok || !x.Malicious || x.Source != "test" {
		t.Fatalf("cache=%#v ok=%v err=%v", x, ok, err)
	}
}

func TestIncidentHistory(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "triage.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	if err = s.SaveIncident(context.Background(), map[string]string{"x": "1"}, "inc-1", "same", "high", 80, 1, now, now); err != nil {
		t.Fatal(err)
	}
	if err = s.AddFeedback(context.Background(), "inc-1", "fp", "", "analyst"); err != nil {
		t.Fatal(err)
	}
	rows, err := s.IncidentHistory(context.Background(), "same", 5)
	if err != nil || len(rows) != 1 || rows[0].Verdict != "fp" {
		t.Fatalf("history=%#v err=%v", rows, err)
	}
}

func TestAPIKeyHashAndVerify(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "triage.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.CreateAPIKey(context.Background(), "bot", "analyst", "secret-value"); err != nil {
		t.Fatal(err)
	}
	role, ok, err := s.VerifyAPIKey(context.Background(), "secret-value")
	if err != nil || !ok || role != "analyst" {
		t.Fatalf("role=%s ok=%v err=%v", role, ok, err)
	}
	if _, ok, err = s.VerifyAPIKey(context.Background(), "wrong"); err != nil || ok {
		t.Fatalf("wrong key ok=%v err=%v", ok, err)
	}
}

func TestIncidentFilters(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "triage.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	old := now.Add(-time.Hour)
	if err = s.SaveIncident(context.Background(), map[string]string{}, "low-1", "a", "low", 10, 1, old, old); err != nil {
		t.Fatal(err)
	}
	if err = s.SaveIncident(context.Background(), map[string]string{}, "high-1", "b", "high", 80, 1, now, now); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListIncidentsFiltered(context.Background(), "high", now.Add(-time.Minute).Format(time.RFC3339Nano), 1)
	if err != nil || len(rows) != 1 || rows[0].ID != "high-1" {
		t.Fatalf("rows=%#v err=%v", rows, err)
	}
}

func TestLatestIncidentByFingerprint(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "triage.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	if err = s.SaveIncident(context.Background(), map[string]string{}, "i", "same", "medium", 50, 2, now, now); err != nil {
		t.Fatal(err)
	}
	r, err := s.LatestIncidentByFingerprint(context.Background(), "same")
	if err != nil || r.ID != "i" || r.AlertCount != 2 {
		t.Fatalf("record=%#v err=%v", r, err)
	}
}

func TestPruneRetention(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "triage.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	old := time.Now().UTC().Add(-48 * time.Hour)
	fresh := time.Now().UTC()
	if err = s.SaveAlert(context.Background(), "old", "file", old, map[string]string{"x": "old"}); err != nil {
		t.Fatal(err)
	}
	if err = s.SaveAlert(context.Background(), "new", "file", fresh, map[string]string{"x": "new"}); err != nil {
		t.Fatal(err)
	}
	if err = s.Prune(context.Background(), time.Now().UTC().Add(-24*time.Hour), time.Time{}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = s.db.QueryRow(`SELECT COUNT(*) FROM alerts`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("alerts=%d err=%v", count, err)
	}
}
