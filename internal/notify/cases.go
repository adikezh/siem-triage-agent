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

type TheHive struct {
	URL, APIKey string
	Client      *http.Client
}

func (t TheHive) Send(ctx context.Context, item store.OutboxItem) error {
	return postCase(ctx, t.URL+"/api/v1/alert", t.APIKey, "x-thehive-user", item, t.Client)
}

type IRIS struct {
	URL, APIKey string
	Client      *http.Client
}

func (i IRIS) Send(ctx context.Context, item store.OutboxItem) error {
	return postCase(ctx, i.URL+"/case", i.APIKey, "x-iris-api-key", item, i.Client)
}
func postCase(ctx context.Context, url, key, header string, item store.OutboxItem, client *http.Client) error {
	if url == "" || key == "" {
		return fmt.Errorf("case system URL and API key are required")
	}
	c := client
	if c == nil {
		c = &http.Client{Timeout: 15 * time.Second}
	}
	body := map[string]any{"title": "SIEM incident " + item.IncidentID, "description": string(item.Payload), "source": "triage"}
	b, _ := json.Marshal(body)
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if e != nil {
		return e
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set(header, key)
	resp, e := c.Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("case system HTTP %s", resp.Status)
	}
	return nil
}
