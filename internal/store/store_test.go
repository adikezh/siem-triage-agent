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
}
