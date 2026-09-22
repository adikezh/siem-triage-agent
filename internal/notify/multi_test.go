package notify

import (
	"context"
	"testing"

	"github.com/adikezh/siem-triage-agent/internal/store"
)

type recordingSender struct{ called bool }

func (s *recordingSender) Send(context.Context, store.OutboxItem) error {
	s.called = true
	return nil
}

func TestMultiRoutesAndListsChannels(t *testing.T) {
	s := &recordingSender{}
	m := Multi{Senders: map[string]Sender{"telegram": s}}
	if len(m.Channels()) != 1 || m.Channels()[0] != "telegram" {
		t.Fatalf("channels=%v", m.Channels())
	}
	if err := m.Send(context.Background(), store.OutboxItem{Channel: "telegram"}); err != nil {
		t.Fatal(err)
	}
	if !s.called {
		t.Fatal("sender was not called")
	}
	if err := m.Send(context.Background(), store.OutboxItem{Channel: "missing"}); err == nil {
		t.Fatal("expected missing channel error")
	}
}
