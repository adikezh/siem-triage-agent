package ingest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGenericClientMapping(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q map[string]any
		_ = json.NewDecoder(r.Body).Decode(&q)
		if q["search_after"] != nil {
			t.Error("unexpected search_after on first page")
		}
		_, _ = w.Write([]byte(`{"hits":{"hits":[{"_id":"e1","_source":{"event":{"time":"2026-09-23T08:00:00Z"},"signal":{"id":"42","severity":9,"text":"login failure"},"host":{"name":"db-1"},"network":{"client":{"ip":"203.0.113.10"}}},"sort":["2026-09-23T08:00:00Z","e1"]}]}}`))
	}))
	defer s.Close()
	c := GenericClient{BaseURL: s.URL, Index: "logs-*", Mapping: map[string]string{"timestamp": "event.time", "rule_id": "signal.id", "rule_level": "signal.severity", "rule_description": "signal.text", "src_ip": "network.client.ip", "agent": "host"}}
	h, next, err := c.Search(context.Background(), Cursor{Timestamp: time.Unix(0, 0)})
	if err != nil || len(h) != 1 || h[0].Source["rule_id"] != "42" || h[0].Source["src_ip"] != "203.0.113.10" || next.Timestamp.IsZero() {
		t.Fatalf("hits=%#v next=%#v err=%v", h, next, err)
	}
}
