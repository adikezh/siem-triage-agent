package metrics

import (
	"fmt"
	"github.com/adikezh/siem-triage-agent/internal/store"
	"net/http"
)

func Handler(s *store.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rows, e := s.ListIncidents(r.Context())
		if e != nil {
			http.Error(w, "storage error", 500)
			return
		}
		counts := map[string]int{}
		for _, x := range rows {
			counts[x.Severity]++
		}
		w.Header().Set("content-type", "text/plain; version=0.0.4")
		fmt.Fprintln(w, "# HELP triage_incidents_total Stored incidents by final severity.")
		fmt.Fprintln(w, "# TYPE triage_incidents_total gauge")
		for _, sev := range []string{"low", "medium", "high", "critical"} {
			fmt.Fprintf(w, "triage_incidents_total{severity=\"%s\"} %d\n", sev, counts[sev])
		}
		m, e := s.Metrics(r.Context())
		if e != nil {
			http.Error(w, "storage error", 500)
			return
		}
		fmt.Fprintln(w, "# TYPE triage_llm_calls_total counter")
		fmt.Fprintf(w, "triage_llm_calls_total %d\ntriage_llm_calls_used_total %d\ntriage_llm_errors_total %d\n", m.LLMCalls, m.LLMUsed, m.LLMErrors)
		fmt.Fprintf(w, "triage_llm_latency_ms_avg %f\n", m.LLMLatencyMS)
		fmt.Fprintf(w, "triage_feedback_total{verdict=\"tp\"} %d\ntriage_feedback_total{verdict=\"fp\"} %d\ntriage_feedback_total{verdict=\"ack\"} %d\n", m.FeedbackTP, m.FeedbackFP, m.FeedbackAck)
		fmt.Fprintf(w, "triage_outbox_total{status=\"pending\"} %d\ntriage_outbox_total{status=\"sent\"} %d\n", m.OutboxPending, m.OutboxSent)
	})
}
