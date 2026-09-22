package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/adikezh/siem-triage-agent/internal/store"
	"net/http"
	"time"
)

type Slack struct {
	URL    string
	Client *http.Client
}

func (s Slack) Send(ctx context.Context, item store.OutboxItem) error {
	if s.URL == "" {
		return fmt.Errorf("slack webhook URL is required")
	}
	c := s.Client
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	elements := []map[string]any{
		{"type": "button", "text": map[string]string{"type": "plain_text", "text": "✅ TP"}, "action_id": "tp", "value": item.IncidentID},
		{"type": "button", "text": map[string]string{"type": "plain_text", "text": "❌ FP"}, "action_id": "fp", "value": item.IncidentID},
		{"type": "button", "text": map[string]string{"type": "plain_text", "text": "👁 Ack"}, "action_id": "ack", "value": item.IncidentID},
		{"type": "button", "text": map[string]string{"type": "plain_text", "text": "🔗 Open"}, "action_id": "open", "value": item.IncidentID},
	}
	body := map[string]any{"text": string(item.Payload), "blocks": []map[string]any{
		{"type": "section", "text": map[string]string{"type": "mrkdwn", "text": string(item.Payload)}},
		{"type": "actions", "elements": elements},
	}}
	b, _ := json.Marshal(body)
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(b))
	if e != nil {
		return e
	}
	req.Header.Set("content-type", "application/json")
	resp, e := c.Do(req)
	if e != nil {
		return fmt.Errorf("slack request: %w", e)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("slack HTTP %s", resp.Status)
	}
	return nil
}
