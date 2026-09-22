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

type Jira struct {
	BaseURL, Username, Token, Project, IssueType string
	Client                                       *http.Client
}

func (j Jira) Send(ctx context.Context, item store.OutboxItem) error {
	if j.BaseURL == "" || j.Username == "" || j.Token == "" || j.Project == "" {
		return fmt.Errorf("jira base URL, credentials and project are required")
	}
	typ := j.IssueType
	if typ == "" {
		typ = "Task"
	}
	c := j.Client
	if c == nil {
		c = &http.Client{Timeout: 15 * time.Second}
	}
	body := map[string]any{"fields": map[string]any{"project": map[string]string{"key": j.Project}, "summary": "SIEM triage incident " + item.IncidentID, "description": string(item.Payload), "issuetype": map[string]string{"name": typ}}}
	b, _ := json.Marshal(body)
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, j.BaseURL+"/rest/api/2/issue", bytes.NewReader(b))
	if e != nil {
		return e
	}
	req.SetBasicAuth(j.Username, j.Token)
	req.Header.Set("content-type", "application/json")
	resp, e := c.Do(req)
	if e != nil {
		return fmt.Errorf("jira request: %w", e)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("jira HTTP %s", resp.Status)
	}
	return nil
}
