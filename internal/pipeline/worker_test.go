package pipeline

import (
	"context"
	"errors"
	"github.com/adikezh/siem-triage-agent/internal/ingest"
	"github.com/adikezh/siem-triage-agent/internal/store"
	"path/filepath"
	"testing"
	"time"
)

type src struct{}

func (src) Search(context.Context, ingest.Cursor) ([]ingest.Hit, ingest.Cursor, error) {
	t := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return []ingest.Hit{{ID: "a", Timestamp: t}}, ingest.Cursor{Timestamp: t, Sort: []any{"x"}}, nil
}

type proc struct{}

func (proc) Process(context.Context, []ingest.Hit) ([]Notification, error) {
	return []Notification{{IncidentID: "i", Channel: "test", Payload: map[string]string{"ok": "yes"}}}, nil
}

type sender struct {
	n    int
	fail bool
}

func (s *sender) Send(context.Context, store.OutboxItem) error {
	s.n++
	if s.fail {
		return errors.New("temporary")
	}
	return nil
}
func TestPollSavesCursorAfterProcessing(t *testing.T) {
	s, e := store.Open(filepath.Join(t.TempDir(), "x.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	w := Worker{SourceName: "wazuh", Source: src{}, Processor: proc{}, Store: s}
	if n, e := w.Poll(context.Background()); e != nil || n != 1 {
		t.Fatalf("poll %d %v", n, e)
	}
	c, _ := s.LoadCursor(context.Background(), "wazuh")
	if c.Timestamp.IsZero() {
		t.Fatal("cursor missing")
	}
	items, _ := s.PendingOutbox(context.Background(), 10)
	if len(items) != 1 {
		t.Fatalf("outbox=%d", len(items))
	}
}
func TestDispatcherBackoffAndSuccess(t *testing.T) {
	s, _ := store.Open(filepath.Join(t.TempDir(), "x.db"))
	defer s.Close()
	_ = s.Enqueue(context.Background(), "i", "test", []byte("x"))
	bad := &sender{fail: true}
	base := time.Now().UTC().Truncate(time.Second)
	d := Dispatcher{Store: s, Sender: bad, BaseDelay: time.Minute, Now: func() time.Time { return base }}
	if _, e := d.Dispatch(context.Background(), 10); e != nil {
		t.Fatal(e)
	}
	ok := &sender{}
	d.Sender = ok
	if n, e := d.Dispatch(context.Background(), 10); e != nil || n != 0 {
		t.Fatalf("early retry delivered: %d %v", n, e)
	}
	_ = s.MarkOutbox(context.Background(), 1, true, time.Now(), "")
}
