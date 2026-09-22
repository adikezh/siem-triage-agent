package report

import (
	"context"
	"fmt"
	"github.com/adikezh/siem-triage-agent/internal/store"
	"sort"
	"strings"
	"time"
)

func Markdown(ctx context.Context, s *store.Store, period time.Duration) (string, error) {
	rows, e := s.ListIncidents(ctx)
	if e != nil {
		return "", e
	}
	since := time.Now().UTC().Add(-period)
	counts := map[string]int{}
	total := 0
	for _, r := range rows {
		t, _ := time.Parse(time.RFC3339Nano, r.LastSeen)
		if t.Before(since) {
			continue
		}
		counts[r.Severity]++
		total++
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	fmt.Fprintf(&b, "# SIEM Triage Report\n\nPeriod: last %s\n\n", period)
	fmt.Fprintf(&b, "Total incidents: **%d**\n\n| Severity | Count |\n|---|---:|\n", total)
	for _, k := range keys {
		fmt.Fprintf(&b, "| %s | %d |\n", k, counts[k])
	}
	if total == 0 {
		b.WriteString("\nNo incidents in the selected period.\n")
	}
	return b.String(), nil
}
