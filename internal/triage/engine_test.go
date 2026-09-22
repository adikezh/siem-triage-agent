package triage

import (
	"context"
	"github.com/adikezh/siem-triage-agent/internal/triage/llm"
	"github.com/adikezh/siem-triage-agent/internal/triage/scoring"
	"testing"
)

type provider struct{ r llm.Response }

func (p provider) Name() string                                                { return "test" }
func (p provider) Complete(context.Context, llm.Request) (llm.Response, error) { return p.r, nil }
func TestEngineThresholdAndMerge(t *testing.T) {
	e := Engine{Threshold: 40, Model: "x", Provider: provider{r: llm.Response{Severity: "low", FPProbability: .8}}, InternalCIDRs: []string{"10.0.0.0/8"}}
	r := e.Analyze(context.Background(), Case{Rule: scoring.Input{RuleLevel: 10}, RuleSeverity: "high", Prompt: llm.PromptInput{Description: "data"}})
	if r.Severity != "low" {
		t.Fatalf("expected FP downgrade, got %#v", r)
	}
	e.Provider = nil
	r = e.Analyze(context.Background(), Case{Rule: scoring.Input{RuleLevel: 1}, RuleSeverity: "low"})
	if r.Trace.Used {
		t.Fatal("threshold/provider gate failed")
	}
}
