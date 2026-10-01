package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/adikezh/siem-triage-agent/internal/ingest"
	"github.com/adikezh/siem-triage-agent/internal/store"
)

type Source interface {
	Search(context.Context, ingest.Cursor) ([]ingest.Hit, ingest.Cursor, error)
}
type Processor interface {
	// Process must only prepare notifications, not persist side effects.
	Process(context.Context, []ingest.Hit) ([]Notification, error)
}
type PageProcessor interface {
	Prepare(context.Context, []ingest.Hit) (store.Page, error)
}
type Notification struct {
	IncidentID, Channel string
	Payload             any
}
type Worker struct {
	SourceName    string
	Source        Source
	Processor     Processor
	PageProcessor PageProcessor
	Store         *store.Store
}

func (w Worker) Poll(ctx context.Context) (int, error) {
	if w.Source == nil || (w.Processor == nil && w.PageProcessor == nil) || w.Store == nil || w.SourceName == "" {
		return 0, fmt.Errorf("pipeline worker dependencies are required")
	}
	saved, e := w.Store.LoadCursor(ctx, w.SourceName)
	if e != nil {
		return 0, e
	}
	cursor, e := ingest.RestoreCursor(saved.Timestamp, saved.SortJSON)
	if e != nil {
		return 0, e
	}
	hits, next, e := w.Source.Search(ctx, cursor)
	if e != nil {
		return 0, e
	}
	ids := make([]string, 0, len(hits))
	for _, hit := range hits {
		if hit.ID == "" || hit.Timestamp.IsZero() {
			return 0, fmt.Errorf("source hit requires ID and timestamp")
		}
		ids = append(ids, hit.ID)
	}
	seen, e := w.Store.ExistingAlertIDs(ctx, ids)
	if e != nil {
		return 0, e
	}
	fresh := make([]ingest.Hit, 0, len(hits))
	for _, hit := range hits {
		if !seen[hit.ID] {
			fresh = append(fresh, hit)
			seen[hit.ID] = true
		}
	}
	var page store.Page
	if len(fresh) > 0 {
		if w.PageProcessor != nil {
			page, e = w.PageProcessor.Prepare(ctx, fresh)
		} else {
			var notes []Notification
			notes, e = w.Processor.Process(ctx, fresh)
			for _, n := range notes {
				b, err := json.Marshal(n.Payload)
				if err != nil {
					return 0, err
				}
				page.Notifications = append(page.Notifications, store.NotificationWrite{IncidentID: n.IncidentID, Channel: n.Channel, Payload: b})
			}
		}
		if e != nil {
			return 0, fmt.Errorf("prepare page: %w", e)
		}
	}
	if page.Alerts == nil {
		for _, hit := range fresh {
			page.Alerts = append(page.Alerts, store.AlertWrite{ID: hit.ID, Source: w.SourceName, Timestamp: hit.Timestamp, Payload: hit.Source})
		}
	}
	// Every fresh hit, including a suppressed alert, must be durably accounted
	// for before its source checkpoint can advance.
	if len(page.Alerts) != len(fresh) {
		return 0, fmt.Errorf("processor omitted source alerts")
	}
	for i, hit := range fresh {
		if page.Alerts[i].ID != hit.ID {
			return 0, fmt.Errorf("processor changed source alert identity")
		}
	}
	sortJSON, e := json.Marshal(next.Sort)
	if e != nil {
		return 0, e
	}
	if e = w.Store.CommitPage(ctx, w.SourceName, saved, store.Cursor{Timestamp: next.Timestamp, SortJSON: sortJSON}, page); e != nil {
		return 0, e
	}
	return len(fresh), nil
}

type Sender interface {
	Send(context.Context, store.OutboxItem) error
}
type Dispatcher struct {
	Store       *store.Store
	Sender      Sender
	BaseDelay   time.Duration
	MaxAttempts int
	RetryWindow time.Duration
	MaxDelay    time.Duration
	Now         func() time.Time
}

func (d Dispatcher) Dispatch(ctx context.Context, limit int) (int, error) {
	if d.Store == nil || d.Sender == nil {
		return 0, fmt.Errorf("dispatcher dependencies are required")
	}
	now := time.Now
	if d.Now != nil {
		now = d.Now
	}
	window := d.RetryWindow
	if window <= 0 {
		window = 24 * time.Hour
	}
	if err := d.Store.ExpireOutboxBefore(ctx, now().Add(-window)); err != nil {
		return 0, err
	}
	items, e := d.Store.PendingOutboxAt(ctx, limit, now())
	if e != nil {
		return 0, e
	}
	sent := 0
	for _, item := range items {
		if err := ctx.Err(); err != nil {
			return sent, err
		}
		deadline := item.CreatedAt.Add(window)
		if !now().Before(deadline) || (d.MaxAttempts > 0 && item.Attempts >= d.MaxAttempts) {
			if err := d.Store.ExpireOutbox(ctx, item.ID, "notification retry window or attempt limit exceeded"); err != nil {
				return sent, err
			}
			continue
		}
		e = d.Sender.Send(ctx, item)
		if ctx.Err() != nil {
			// A cancelled attempt remains pending and is retried after restart.
			return sent, ctx.Err()
		}
		if e == nil {
			if err := d.Store.MarkOutbox(ctx, item.ID, true, now(), ""); err != nil {
				return sent, fmt.Errorf("record delivered notification: %w", err)
			}
			sent++
			continue
		}
		delay := d.BaseDelay
		if delay <= 0 {
			delay = time.Second
		}
		maxDelay := d.MaxDelay
		if maxDelay <= 0 {
			maxDelay = time.Hour
		}
		delay = min(delay, maxDelay)
		for attempt := 0; attempt < item.Attempts && delay < maxDelay; attempt++ {
			if delay > maxDelay/2 {
				delay = maxDelay
			} else {
				delay *= 2
			}
		}
		next := now().Add(delay)
		if next.After(deadline) {
			next = deadline
		}
		status := "pending"
		if !now().Before(deadline) || (d.MaxAttempts > 0 && item.Attempts+1 >= d.MaxAttempts) {
			status = "failed"
		}
		if me := d.Store.RecordOutboxAttempt(ctx, item.ID, status, next, e.Error()); me != nil {
			return sent, me
		}
	}
	return sent, nil
}

// Run retries the durable outbox independently of source polling. A source
// outage therefore does not stall already queued notifications.
func (d Dispatcher) Run(ctx context.Context, interval time.Duration, limit int, onError func(error)) error {
	if interval <= 0 {
		return fmt.Errorf("dispatch interval must be positive")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if _, err := d.Dispatch(ctx, limit); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if onError != nil {
				onError(err)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
