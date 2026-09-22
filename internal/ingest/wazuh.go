package ingest

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type WazuhClient struct {
	BaseURL, Index, Username, Password string
	InsecureSkipVerify                 bool
	HTTPClient                         *http.Client
	PageSize                           int
}
type Cursor struct {
	Timestamp time.Time
	Sort      []any
}
type Hit struct {
	ID        string
	Timestamp time.Time
	Source    map[string]any
	Sort      []any
}

func (c WazuhClient) Search(ctx context.Context, cursor Cursor) ([]Hit, Cursor, error) {
	if c.BaseURL == "" || c.Index == "" {
		return nil, cursor, fmt.Errorf("wazuh base URL and index are required")
	}
	hc := c.HTTPClient
	if hc == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: c.InsecureSkipVerify}
		hc = &http.Client{Transport: tr, Timeout: 30 * time.Second}
	}
	size := c.PageSize
	if size <= 0 {
		size = 1000
	}
	q := map[string]any{"size": size, "sort": []string{"@timestamp", "_id"}, "query": map[string]any{"range": map[string]any{"@timestamp": map[string]string{"gt": cursor.Timestamp.UTC().Format(time.RFC3339Nano)}}}}
	if len(cursor.Sort) > 0 {
		q["search_after"] = cursor.Sort
	}
	b, _ := json.Marshal(q)
	u := strings.TrimRight(c.BaseURL, "/") + "/" + url.PathEscape(c.Index) + "/_search"
	r, e := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if e != nil {
		return nil, cursor, e
	}
	r.Header.Set("content-type", "application/json")
	if c.Username != "" {
		r.SetBasicAuth(c.Username, c.Password)
	}
	resp, e := hc.Do(r)
	if e != nil {
		return nil, cursor, e
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, cursor, fmt.Errorf("wazuh HTTP %s", resp.Status)
	}
	var body struct {
		Hits struct {
			Hits []struct {
				ID     string         `json:"_id"`
				Source map[string]any `json:"_source"`
				Sort   []any          `json:"sort"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if e = json.NewDecoder(resp.Body).Decode(&body); e != nil {
		return nil, cursor, e
	}
	out := make([]Hit, 0, len(body.Hits.Hits))
	next := cursor
	for _, h := range body.Hits.Hits {
		ts := extractTime(h.Source)
		out = append(out, Hit{ID: h.ID, Timestamp: ts, Source: h.Source, Sort: h.Sort})
		if ts.After(next.Timestamp) {
			next.Timestamp = ts
		}
		if len(h.Sort) > 0 {
			next.Sort = h.Sort
		}
	}
	return out, next, nil
}
func extractTime(m map[string]any) time.Time {
	for _, k := range []string{"@timestamp", "timestamp"} {
		if s, ok := m[k].(string); ok {
			if t, e := time.Parse(time.RFC3339Nano, s); e == nil {
				return t
			}
		}
	}
	return time.Time{}
}
func AlertFromHit(h Hit) map[string]any {
	a := map[string]any{"id": h.ID, "source": "wazuh", "timestamp": h.Timestamp.Format(time.RFC3339Nano)}
	for k, v := range h.Source {
		a[k] = v
	}
	return a
}

func NormalizeHit(h Hit) map[string]any {
	out := AlertFromHit(h)
	if rule, ok := h.Source["rule"].(map[string]any); ok {
		if id, ok := rule["id"]; ok {
			out["rule_id"] = id
		}
		if l, ok := rule["level"]; ok {
			out["rule_level"] = l
		}
		if d, ok := rule["description"]; ok {
			out["rule_description"] = d
		}
		if g, ok := rule["groups"]; ok {
			out["groups"] = g
		}
		if mitre, ok := rule["mitre"].(map[string]any); ok {
			if tactics, ok := mitre["tactic"]; ok {
				out["mitre_tactics"] = tactics
			}
			if techniques, ok := mitre["technique"]; ok {
				out["mitre_techniques"] = techniques
			}
		}
	}
	if agent, ok := h.Source["agent"].(map[string]any); ok {
		out["agent"] = agent
	}
	if data, ok := h.Source["data"].(map[string]any); ok {
		for _, field := range []struct{ from, to string }{
			{"srcip", "src_ip"}, {"dstip", "dst_ip"}, {"src_ip", "src_ip"}, {"dst_ip", "dst_ip"}, {"user", "user"}, {"process", "process"},
		} {
			if v, ok := data[field.from]; ok {
				out[field.to] = v
			}
		}
	}
	return out
}
