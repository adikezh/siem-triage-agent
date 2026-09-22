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

// GenericClient reads Elasticsearch/OpenSearch indices and maps arbitrary
// source fields into the normalized alert shape used by the pipeline.
type GenericClient struct {
	BaseURL, Index, Username, Password string
	InsecureSkipVerify                 bool
	HTTPClient                         *http.Client
	PageSize                           int
	Mapping                            map[string]string // normalized name -> dotted source path
}

func (c GenericClient) Search(ctx context.Context, cursor Cursor) ([]Hit, Cursor, error) {
	if c.BaseURL == "" || c.Index == "" {
		return nil, cursor, fmt.Errorf("generic base URL and index are required")
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
	timeField := c.field("timestamp", "@timestamp")
	q := map[string]any{"size": size, "sort": []string{timeField, "_id"}, "query": map[string]any{"range": map[string]any{timeField: map[string]string{"gt": cursor.Timestamp.UTC().Format(time.RFC3339Nano)}}}}
	if len(cursor.Sort) > 0 {
		q["search_after"] = cursor.Sort
	}
	b, _ := json.Marshal(q)
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+"/"+url.PathEscape(c.Index)+"/_search", bytes.NewReader(b))
	if err != nil {
		return nil, cursor, err
	}
	r.Header.Set("content-type", "application/json")
	if c.Username != "" {
		r.SetBasicAuth(c.Username, c.Password)
	}
	resp, err := hc.Do(r)
	if err != nil {
		return nil, cursor, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, cursor, fmt.Errorf("generic search HTTP %s", resp.Status)
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
	if err = json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, cursor, err
	}
	out := make([]Hit, 0, len(body.Hits.Hits))
	next := cursor
	for _, raw := range body.Hits.Hits {
		ts := valueTime(raw.Source, c.field("timestamp", "@timestamp"))
		source := c.normalize(raw.Source)
		out = append(out, Hit{ID: raw.ID, Timestamp: ts, Source: source, Sort: raw.Sort})
		if ts.After(next.Timestamp) {
			next.Timestamp = ts
		}
		if len(raw.Sort) > 0 {
			next.Sort = raw.Sort
		}
	}
	return out, next, nil
}

func (c GenericClient) field(name, fallback string) string {
	if v := c.Mapping[name]; v != "" {
		return v
	}
	return fallback
}

func (c GenericClient) normalize(raw map[string]any) map[string]any {
	out := map[string]any{"source": "elastic"}
	for k, v := range raw {
		out[k] = v
	}
	for _, name := range []string{"timestamp", "rule_id", "rule_level", "rule_description", "groups", "agent", "src_ip", "dst_ip", "user", "process"} {
		if path := c.Mapping[name]; path != "" {
			if v, ok := dotted(raw, path); ok {
				out[name] = v
			}
		}
	}
	if v, ok := out["timestamp"].(string); ok {
		out["timestamp"] = v
	}
	return out
}

func valueTime(m map[string]any, path string) time.Time {
	v, ok := dotted(m, path)
	if !ok {
		return time.Time{}
	}
	s, ok := v.(string)
	if !ok {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}
func dotted(m map[string]any, path string) (any, bool) {
	var cur any = m
	for _, p := range strings.Split(path, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = obj[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}
