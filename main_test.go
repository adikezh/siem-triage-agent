package main

import (
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
