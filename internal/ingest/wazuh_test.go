package ingest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWazuhSearchAfterAndCursor(t *testing.T) {
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var q map[string]any
		_ = json.NewDecoder(r.Body).Decode(&q)
		if q["size"] != float64(2) {
			t.Errorf("size=%v", q["size"])
		}
		if calls == 2 && q["search_after"] == nil {
			t.Error("missing search_after")
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"hits":{"hits":[{"_id":"a1","_source":{"@timestamp":"2026-09-23T08:00:00Z"},"sort":["2026-09-23T08:00:00Z","a1"]},{"_id":"a2","_source":{"@timestamp":"2026-09-23T08:01:00Z"},"sort":["2026-09-23T08:01:00Z","a2"]}]}}`))
	}))
	defer s.Close()
	c := WazuhClient{BaseURL: s.URL, Index: "wazuh-alerts-*", PageSize: 2}
	h, n, e := c.Search(context.Background(), Cursor{Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})
	if e != nil || len(h) != 2 || n.Timestamp.Minute() != 1 {
		t.Fatalf("result %#v %#v %v", h, n, e)
	}
	_, _, _ = c.Search(context.Background(), n)
	if calls != 2 {
		t.Fatal("expected two polls")
	}
}

func TestNormalizeHitMapsWazuhDataFields(t *testing.T) {
	h := Hit{ID: "x", Timestamp: time.Now(), Source: map[string]any{
		"rule":  map[string]any{"id": "100", "level": 8, "groups": []any{"authentication_failed"}, "mitre": map[string]any{"tactic": []any{"Credential Access"}, "technique": []any{"T1110"}}},
		"agent": map[string]any{"id": "a1"},
		"data":  map[string]any{"srcip": "203.0.113.8", "dstip": "10.0.0.2"},
	}}
	got := NormalizeHit(h)
	if got["src_ip"] != "203.0.113.8" || got["dst_ip"] != "10.0.0.2" {
		t.Fatalf("normalized data=%#v", got)
	}
	if _, ok := got["srcip"]; ok {
		t.Fatalf("legacy srcip key leaked into normalized model: %#v", got)
	}
	if got["mitre_tactics"] == nil || got["mitre_techniques"] == nil {
		t.Fatalf("MITRE fields were not normalized: %#v", got)
	}
}
