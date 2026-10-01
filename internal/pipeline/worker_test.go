package pipeline

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/adikezh/siem-triage-agent/internal/ingest"
	"github.com/adikezh/siem-triage-agent/internal/store"
)

type src struct{}

func (src) Search(context.Context, ingest.Cursor) ([]ingest.Hit, ingest.Cursor, error) {
	t := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return []ingest.Hit{{ID: "a", Timestamp: t}}, ingest.Cursor{Timestamp: t, Sort: []any{"x"}}, nil
}

type sourceFunc func(context.Context, ingest.Cursor) ([]ingest.Hit, ingest.Cursor, error)

func (f sourceFunc) Search(ctx context.Context, c ingest.Cursor) ([]ingest.Hit, ingest.Cursor, error) {
	return f(ctx, c)
}

func TestPollRestoresFullCursorAfterRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "restart.db")
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := s.SaveCursor(context.Background(), "wazuh", store.Cursor{Timestamp: stamp, SortJSON: []byte(`["2026-01-01T00:00:00Z","alert-1"]`)}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	source := sourceFunc(func(_ context.Context, c ingest.Cursor) ([]ingest.Hit, ingest.Cursor, error) {
		if !c.Timestamp.Equal(stamp) || !reflect.DeepEqual(c.Sort, []any{"2026-01-01T00:00:00Z", "alert-1"}) {
			t.Fatalf("restart cursor lost its tie-breaker: %#v", c)
		}
		return nil, c, nil
	})
	if _, err := (Worker{SourceName: "wazuh", Source: source, Processor: proc{}, Store: s}).Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
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
	s, err := store.Open(filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Enqueue(context.Background(), "i", "test", []byte("x")); err != nil {
		t.Fatal(err)
	}
	bad := &sender{fail: true}
	base := time.Now().UTC().Add(time.Second)
	d := Dispatcher{Store: s, Sender: bad, BaseDelay: time.Minute, Now: func() time.Time { return base }}
	if _, e := d.Dispatch(context.Background(), 10); e != nil {
		t.Fatal(e)
	}
	if bad.n != 1 {
		t.Fatalf("first attempt count=%d", bad.n)
	}
	items, err := s.PendingOutboxAt(context.Background(), 10, base.Add(time.Minute))
	if err != nil || len(items) != 1 || items[0].Attempts != 1 || !items[0].NextAttemptAt.Equal(base.Add(time.Minute)) {
		t.Fatalf("retry was not scheduled: %#v %v", items, err)
	}
	ok := &sender{}
	d.Sender = ok
	if n, e := d.Dispatch(context.Background(), 10); e != nil || n != 0 {
		t.Fatalf("early retry delivered: %d %v", n, e)
	}
	base = base.Add(time.Minute)
	if n, err := d.Dispatch(context.Background(), 10); err != nil || n != 1 || ok.n != 1 {
		t.Fatalf("due retry did not deliver: n=%d calls=%d err=%v", n, ok.n, err)
	}
	m, err := s.Metrics(context.Background())
	if err != nil || m.OutboxPending != 0 || m.OutboxSent != 1 {
		t.Fatalf("delivery status=%#v err=%v", m, err)
	}
}

type senderFunc func(context.Context, store.OutboxItem) error

func (f senderFunc) Send(ctx context.Context, item store.OutboxItem) error { return f(ctx, item) }

func TestDispatcherExpiresAfter24HoursWithoutSending(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "expiry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if err := s.Enqueue(ctx, "i", "test", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	bad := &sender{fail: true}
	base := time.Now().UTC().Add(23 * time.Hour)
	d := Dispatcher{Store: s, Sender: bad, BaseDelay: 2 * time.Hour, Now: func() time.Time { return base }}
	if _, err := d.Dispatch(ctx, 10); err != nil || bad.n != 1 {
		t.Fatalf("within retry window calls=%d err=%v", bad.n, err)
	}
	base = base.Add(2 * time.Hour)
	// An old version postponed exhausted retries by a year. Such records must
	// expire at 24 hours, not stay invisibly pending until their next due date.
	if err := s.MarkOutbox(ctx, 1, false, base.Add(365*24*time.Hour), "legacy delay"); err != nil {
		t.Fatal(err)
	}
	if n, err := d.Dispatch(ctx, 10); err != nil || n != 0 || bad.n != 1 {
		t.Fatalf("expired item sent: n=%d calls=%d err=%v", n, bad.n, err)
	}
	m, err := s.Metrics(ctx)
	if err != nil || m.OutboxPending != 0 || m.OutboxFailed != 1 {
		t.Fatalf("expired delivery status=%#v err=%v", m, err)
	}
}

func TestDispatcherReportsFailureToRecordSuccessfulSend(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "write-failure.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if err := s.Enqueue(ctx, "i", "test", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	d := Dispatcher{Store: s, Sender: senderFunc(func(context.Context, store.OutboxItem) error {
		// Simulate a storage failure after the recipient accepts the message.
		return s.Close()
	})}
	if n, err := d.Dispatch(ctx, 10); err == nil || n != 0 {
		t.Fatalf("must not claim an unrecorded success: n=%d err=%v", n, err)
	}
}

func TestDispatcherRunDrainsExistingOutboxWithoutSource(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "drain.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Enqueue(context.Background(), "i", "test", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	delivered := make(chan struct{}, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	d := Dispatcher{Store: s, Sender: senderFunc(func(context.Context, store.OutboxItem) error {
		delivered <- struct{}{}
		return nil
	})}
	go func() { done <- d.Run(ctx, time.Millisecond, 10, nil) }()
	select {
	case <-delivered:
	case <-ctx.Done():
		t.Fatal("delivery required source polling")
	}
	for {
		m, err := s.Metrics(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if m.OutboxSent == 1 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("delivery was not recorded")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("dispatcher shutdown=%v", err)
	}
}
