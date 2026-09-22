package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/adikezh/siem-triage-agent/internal/ingest"
	"github.com/adikezh/siem-triage-agent/internal/store"
)

type Source interface {
	Search(context.Context, ingest.Cursor) ([]ingest.Hit, ingest.Cursor, error)
}
type Processor interface {
	Process(context.Context, []ingest.Hit) ([]Notification, error)
}
type Notification struct {
	IncidentID, Channel string
	Payload             any
}
type Worker struct {
	SourceName string
	Source     Source
	Processor  Processor
	Store      *store.Store
}

func (w Worker) Poll(ctx context.Context) (int, error) {
	if w.Source == nil || w.Processor == nil || w.Store == nil {
		return 0, fmt.Errorf("pipeline worker dependencies are required")
	}
	saved, e := w.Store.LoadCursor(ctx, w.SourceName)
	if e != nil {
		return 0, e
	}
	hits, next, e := w.Source.Search(ctx, ingest.Cursor{Timestamp: saved.Timestamp})
	if e != nil {
		return 0, e
	}
	notes, e := w.Processor.Process(ctx, hits)
	if e != nil {
		return 0, fmt.Errorf("process page: %w", e)
	}
	for _, n := range notes {
		b, e := json.Marshal(n.Payload)
		if e != nil {
			return 0, e
		}
		if e = w.Store.Enqueue(ctx, n.IncidentID, n.Channel, b); e != nil {
			return 0, e
		}
	}
	sortJSON, _ := json.Marshal(next.Sort)
	if e = w.Store.SaveCursor(ctx, w.SourceName, store.Cursor{Timestamp: next.Timestamp, SortJSON: sortJSON}); e != nil {
		return 0, e
	}
	return len(hits), nil
}

type Sender interface {
	Send(context.Context, store.OutboxItem) error
}
type Dispatcher struct {
	Store       *store.Store
	Sender      Sender
	BaseDelay   time.Duration
	MaxAttempts int
	Now         func() time.Time
}

func (d Dispatcher) Dispatch(ctx context.Context, limit int) (int, error) {
	if d.Store == nil || d.Sender == nil {
		return 0, fmt.Errorf("dispatcher dependencies are required")
	}
	items, e := d.Store.PendingOutbox(ctx, limit)
	if e != nil {
		return 0, e
	}
	now := time.Now
	if d.Now != nil {
		now = d.Now
	}
	sent := 0
	for _, item := range items {
		e = d.Sender.Send(ctx, item)
		if e == nil {
			sent++
			_ = d.Store.MarkOutbox(ctx, item.ID, true, now(), "")
			continue
		}
		delay := d.BaseDelay
		if delay <= 0 {
			delay = time.Second
		}
		attempt := item.Attempts + 1
		if attempt > 10 {
			attempt = 10
		}
		next := now().Add(delay * time.Duration(math.Pow(2, float64(attempt-1))))
		if d.MaxAttempts > 0 && attempt >= d.MaxAttempts {
			next = now().Add(365 * 24 * time.Hour)
		}
		if me := d.Store.MarkOutbox(ctx, item.ID, false, next, e.Error()); me != nil {
			return sent, me
		}
	}
	return sent, nil
}
