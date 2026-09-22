package main

import (
	"fmt"
	"testing"
	"time"
)

func TestGroupWindow(t *testing.T) {
	b := time.Now().UTC()
	a := []Alert{{ID: "1", Timestamp: b, RuleID: "r", RuleLevel: 10, Agent: map[string]any{"id": "a"}, SrcIP: "1.2.3.4"}, {ID: "2", Timestamp: b.Add(10 * time.Minute), RuleID: "r", RuleLevel: 10, Agent: map[string]any{"id": "a"}, SrcIP: "1.2.3.4"}, {ID: "3", Timestamp: b.Add(30 * time.Minute), RuleID: "r", RuleLevel: 10, Agent: map[string]any{"id": "a"}, SrcIP: "1.2.3.4"}}
	x := group(a)
	if len(x) != 2 || x[0].AlertCount != 2 {
		t.Fatalf("got %#v", x)
	}
}

func BenchmarkGroup100K(b *testing.B) {
	alerts := make([]Alert, 100000)
	base := time.Now().UTC()
	for i := range alerts {
		alerts[i] = Alert{ID: fmt.Sprint(i), Timestamp: base.Add(time.Duration(i) * time.Second), RuleID: "r", Agent: map[string]any{"id": "a"}, SrcIP: "1.2.3.4", RuleLevel: 5}
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = group(alerts)
	}
}
