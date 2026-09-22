package notify

import (
	"context"
	"fmt"

	"github.com/adikezh/siem-triage-agent/internal/store"
)

// Multi routes each outbox item to the sender selected by its channel.
// It also exposes the configured channels so the ingest loop can fan out
// one incident into independent, idempotent outbox records.
type Multi struct {
	Senders map[string]Sender
}

type Sender interface {
	Send(context.Context, store.OutboxItem) error
}

func (m Multi) Channels() []string {
	out := make([]string, 0, len(m.Senders))
	for channel := range m.Senders {
		out = append(out, channel)
	}
	return out
}

func (m Multi) Send(ctx context.Context, item store.OutboxItem) error {
	sender, ok := m.Senders[item.Channel]
	if !ok {
		return fmt.Errorf("notification channel %q is not configured", item.Channel)
	}
	return sender.Send(ctx, item)
}
