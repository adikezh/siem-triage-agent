package eval

import (
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	r, e := Run(strings.NewReader("{\"Verdict\":\"tp\",\"Payload\":{\"severity\":\"high\"}}\n{\"Verdict\":\"fp\",\"Payload\":{\"severity\":\"critical\"}}\n{\"Verdict\":\"tp\",\"Payload\":{\"severity\":\"low\"}}\n"))
	if e != nil || r.TP != 1 || r.FP != 1 || r.FN != 1 || r.Precision != .5 || r.Recall != .5 {
		t.Fatalf("%#v %v", r, e)
	}
}
