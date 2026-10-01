package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestCommitPageRollsBackEveryEffectOnWriteFailure(t *testing.T) {
	for _, table := range []string{"outbox", "source_cursors"} {
		t.Run(table, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "page.db")
			s, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { s.Close() }()
			ctx := context.Background()
			now := time.Now().UTC()
			next := Cursor{Timestamp: now, SortJSON: []byte(`[1790920000000000001,"a1"]`)}
			page := Page{
				Alerts:        []AlertWrite{{ID: "a1", Source: "wazuh", Timestamp: now, Payload: map[string]string{"rule_id": "1"}}},
				Incidents:     []IncidentWrite{{ID: "i1", Fingerprint: "fp", Severity: "high", Score: 60, Count: 1, FirstSeen: now, LastSeen: now, Payload: map[string]int{"alert_count": 1}}},
				Traces:        []LLMTrace{{IncidentID: "i1", Provider: "test", PromptHash: "hash"}},
				Notifications: []NotificationWrite{{IncidentID: "i1", Channel: "webhook", Payload: []byte(`{"ok":true}`)}},
			}
			if _, err := s.db.Exec(`CREATE TRIGGER reject_page BEFORE INSERT ON ` + table + ` BEGIN SELECT RAISE(ABORT, 'injected write failure'); END`); err != nil {
				t.Fatal(err)
			}
			if err := s.CommitPage(ctx, "wazuh", Cursor{}, next, page); err == nil {
				t.Fatal("injected failure was swallowed")
			}
			for _, name := range []string{"alerts", "incidents", "llm_calls", "outbox", "source_cursors"} {
				var count int
				if err := s.db.QueryRow(`SELECT COUNT(*) FROM ` + name).Scan(&count); err != nil || count != 0 {
					t.Fatalf("partial commit to %s: count=%d err=%v", name, count, err)
				}
			}
			if _, err := s.db.Exec(`DROP TRIGGER reject_page`); err != nil {
				t.Fatal(err)
			}
			if err := s.CommitPage(ctx, "wazuh", Cursor{}, next, page); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = Open(path)
			if err != nil {
				t.Fatal(err)
			}
			cursor, err := s.LoadCursor(ctx, "wazuh")
			if err != nil || !cursor.Timestamp.Equal(now) || string(cursor.SortJSON) != string(next.SortJSON) {
				t.Fatalf("restart checkpoint=%#v err=%v", cursor, err)
			}
			for _, name := range []string{"alerts", "incidents", "llm_calls", "outbox", "source_cursors"} {
				var count int
				if err := s.db.QueryRow(`SELECT COUNT(*) FROM ` + name).Scan(&count); err != nil || count != 1 {
					t.Fatalf("durable %s count=%d err=%v", name, count, err)
				}
			}
			if err := s.CommitPage(ctx, "wazuh", Cursor{}, next, page); !errors.Is(err, ErrPageConflict) {
				t.Fatalf("stale writer must not commit: %v", err)
			}
			if err := s.CommitPage(ctx, "wazuh", cursor, next, page); !errors.Is(err, ErrPageConflict) {
				t.Fatalf("duplicate alert must not increment incidents: %v", err)
			}
		})
	}
}

func TestCommitPageCancellationDoesNotAdvanceCursor(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "cancel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = s.CommitPage(ctx, "wazuh", Cursor{}, Cursor{Timestamp: time.Now(), SortJSON: []byte(`[]`)}, Page{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled commit=%v", err)
	}
	cursor, err := s.LoadCursor(context.Background(), "wazuh")
	if err != nil || !cursor.Timestamp.IsZero() {
		t.Fatalf("cancelled cursor=%#v err=%v", cursor, err)
	}
}
