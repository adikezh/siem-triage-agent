package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/adikezh/siem-triage-agent/internal/store"
	"net/http"
	"time"
)

type Webhook struct {
	URL, Secret string
	Client      *http.Client
}

func (w Webhook) Send(ctx context.Context, item store.OutboxItem) error {
	if w.URL == "" {
		return fmt.Errorf("webhook URL is required")
	}
	c := w.Client
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(item.Payload))
	if e != nil {
		return e
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-triage-event", item.Channel)
	mac := hmac.New(sha256.New, []byte(w.Secret))
	_, _ = mac.Write(item.Payload)
	req.Header.Set("x-triage-signature", hex.EncodeToString(mac.Sum(nil)))
	resp, e := c.Do(req)
	if e != nil {
		return fmt.Errorf("webhook request: %w", e)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("webhook HTTP %s", resp.Status)
	}
	return nil
}
