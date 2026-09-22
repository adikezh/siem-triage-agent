package metrics

import (
	"context"
	"github.com/adikezh/siem-triage-agent/internal/store"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHandler(t *testing.T) {
	s, _ := store.Open(filepath.Join(t.TempDir(), "m.db"))
	defer s.Close()
	n := time.Now()
	_ = s.SaveIncident(context.Background(), map[string]string{}, "i", "f", "critical", 90, 1, n, n)
	_ = s.SaveLLMTrace(context.Background(), store.LLMTrace{IncidentID: "i", Provider: "test", Used: true, LatencyMS: 120})
	_ = s.AddFeedback(context.Background(), "i", "fp", "", "analyst")
	w := httptest.NewRecorder()
	Handler(s).ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(w.Body.String(), `triage_incidents_total{severity="critical"} 1`) {
		t.Fatal(w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "triage_llm_latency_ms_avg 120") || !strings.Contains(w.Body.String(), `triage_feedback_total{verdict="fp"} 1`) {
		t.Fatal(w.Body.String())
	}
}
