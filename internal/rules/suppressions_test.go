package rules

import (
	"testing"
	"time"
)

func TestEvaluateCIDRAndExpiry(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ss := []Suppression{{Match: Match{SrcIP: "10.0.0.0/8"}, Action: "drop", Reason: "trusted"}}
	d := Evaluate(Alert{SrcIP: "10.2.3.4"}, ss, now)
	if !d.Suppressed {
		t.Fatal("expected drop")
	}
	expired := now.Add(-time.Hour)
	ss[0].ExpiresAt = &expired
	if Evaluate(Alert{SrcIP: "10.2.3.4"}, ss, now).Suppressed {
		t.Fatal("expired rule matched")
	}
}
