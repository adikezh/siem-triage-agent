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
	})
}
