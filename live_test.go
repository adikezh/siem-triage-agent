package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/adikezh/siem-triage-agent/internal/config"
	"github.com/adikezh/siem-triage-agent/internal/ingest"
	"github.com/adikezh/siem-triage-agent/internal/notify"
	"github.com/adikezh/siem-triage-agent/internal/pipeline"
	"github.com/adikezh/siem-triage-agent/internal/store"
)

type pageSource struct{ hits []ingest.Hit }

func (s *pageSource) Search(_ context.Context, c ingest.Cursor) ([]ingest.Hit, ingest.Cursor, error) {
	if len(s.hits) > 0 {
		last := s.hits[len(s.hits)-1]
		c = ingest.Cursor{Timestamp: last.Timestamp, Sort: []any{last.Timestamp.Format(time.RFC3339Nano), last.ID}}
	}
	return s.hits, c, nil
}

func liveHit(id string) ingest.Hit {
	stamp := time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC)
	return ingest.Hit{ID: id, Timestamp: stamp, Source: map[string]any{
		"rule":  map[string]any{"id": "100", "level": 8},
		"agent": map[string]any{"id": "agent-1"},
		"data":  map[string]any{"srcip": "203.0.113.8"},
	}}
}

func newLiveWorker(db *store.Store, source *pageSource) pipeline.Worker {
	return pipeline.Worker{SourceName: "wazuh-live", Source: source, Store: db, PageProcessor: liveProcessor{
		db: db, correlationWindow: 15 * time.Minute, maxIncidentAge: 6 * time.Hour,
		grouping: config.Defaults().Correlation.Grouping,
		sender:   notify.Multi{Senders: map[string]notify.Sender{"webhook": notify.Webhook{URL: "http://unused.invalid"}}},
	}}
}

func TestLiveReplayAfterRestartDoesNotDoubleIncidentCount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "live-restart.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if db != nil {
			db.Close()
		}
	}()
	ctx := context.Background()
	source := &pageSource{hits: []ingest.Hit{liveHit("a1")}}
	worker := newLiveWorker(db, source)
	if n, err := worker.Poll(ctx); err != nil || n != 1 {
		t.Fatalf("first page=%d %v", n, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	worker = newLiveWorker(db, source)
	// Replay a committed hit alongside a new hit at exactly the same timestamp.
	source.hits = []ingest.Hit{liveHit("a1"), liveHit("a2"), liveHit("a2")}
	if n, err := worker.Poll(ctx); err != nil || n != 1 {
		t.Fatalf("restart page=%d %v", n, err)
	}
	if n, err := worker.Poll(ctx); err != nil || n != 0 {
		t.Fatalf("replay page=%d %v", n, err)
	}
	rows, err := db.ListIncidents(ctx)
	if err != nil || len(rows) != 1 || rows[0].AlertCount != 2 {
		t.Fatalf("replay changed incident count: %#v %v", rows, err)
	}
	items, err := db.PendingOutbox(ctx, 10)
	if err != nil || len(items) != 1 {
		t.Fatalf("duplicate notification: %#v %v", items, err)
	}
	ids, err := db.ExistingAlertIDs(ctx, []string{"a1", "a2"})
	if err != nil || len(ids) != 2 {
		t.Fatalf("alerts not durable: %#v %v", ids, err)
	}
}

func TestLiveInvalidSuppressionStopsCheckpoint(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "invalid-rule.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if _, err := db.CreateSuppressionWithMatch(ctx, "", `{invalid`, "drop", "broken", "", "test"); err != nil {
		t.Fatal(err)
	}
	worker := newLiveWorker(db, &pageSource{hits: []ingest.Hit{liveHit("a1")}})
	if _, err := worker.Poll(ctx); err == nil {
		t.Fatal("malformed suppression was silently ignored")
	}
	c, err := db.LoadCursor(ctx, "wazuh-live")
	if err != nil || !c.Timestamp.IsZero() {
		t.Fatalf("checkpoint advanced past invalid rule: %#v %v", c, err)
	}
	ids, err := db.ExistingAlertIDs(ctx, []string{"a1"})
	if err != nil || len(ids) != 0 {
		t.Fatalf("partial alert save: %#v %v", ids, err)
	}
}

func TestLiveSuppressedAlertIsDurablyAccountedFor(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "suppressed.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if _, err := db.CreateSuppressionWithMatch(ctx, "", `{"rule_id":"100"}`, "drop", "known noise", "", "test"); err != nil {
		t.Fatal(err)
	}
	worker := newLiveWorker(db, &pageSource{hits: []ingest.Hit{liveHit("a1")}})
	if n, err := worker.Poll(ctx); err != nil || n != 1 {
		t.Fatalf("suppressed page=%d %v", n, err)
	}
	rows, err := db.ListIncidents(ctx)
	if err != nil || len(rows) != 0 {
		t.Fatalf("suppression created incidents: %#v %v", rows, err)
	}
	ids, err := db.ExistingAlertIDs(ctx, []string{"a1"})
	if err != nil || !ids["a1"] {
		t.Fatalf("suppressed alert was discarded: %#v %v", ids, err)
	}
	if n, err := worker.Poll(ctx); err != nil || n != 0 {
		t.Fatalf("suppressed replay=%d %v", n, err)
	}
}
