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

type Telegram struct {
	BaseURL, Token, ChatID string
	Client                 *http.Client
}

func (t Telegram) Send(ctx context.Context, item store.OutboxItem) error {
	if t.Token == "" || t.ChatID == "" {
		return fmt.Errorf("telegram token and chat id are required")
	}
	c := t.Client
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	body := map[string]any{"chat_id": t.ChatID, "text": string(item.Payload), "parse_mode": "HTML"}
	b, _ := json.Marshal(body)
	u := t.BaseURL
	if u == "" {
		u = "https://api.telegram.org"
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, u+"/bot"+t.Token+"/sendMessage", bytes.NewReader(b))
	if e != nil {
		return e
	}
	req.Header.Set("content-type", "application/json")
	resp, e := c.Do(req)
	if e != nil {
		return fmt.Errorf("telegram request: %w", e)
	}
	defer resp.Body.Close()
	var result struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	if e = json.NewDecoder(resp.Body).Decode(&result); e != nil {
		return e
	}
	if resp.StatusCode/100 != 2 || !result.OK {
		return fmt.Errorf("telegram error: %s", result.Description)
	}
	return nil
}
