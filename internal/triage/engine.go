package triage

import (
	"context"
	"time"

	"github.com/adikezh/siem-triage-agent/internal/triage/llm"
	"github.com/adikezh/siem-triage-agent/internal/triage/scoring"
)

type Case struct {
	Rule         scoring.Input
	RuleSeverity string
	Prompt       llm.PromptInput
}
type Trace struct {
	Provider   string `json:"provider"`
	PromptHash string `json:"prompt_hash"`
	Model      string `json:"model"`
	LatencyMS  int64  `json:"latency_ms"`
	Used       bool   `json:"used"`
	Error      string `json:"error,omitempty"`
}
type Result struct {
	Severity      string
	Score         int
	Summary       string
	Actions       []string
	FPProbability float64
	Trace         Trace
}
type Engine struct {
	Threshold     int
	Language      string
	Provider      llm.Provider
	Model         string
	InternalCIDRs []string
	Now           func() time.Time
}

func (e Engine) Analyze(ctx context.Context, c Case) Result {
	score := scoring.Score(c.Rule)
	out := Result{Severity: c.RuleSeverity, Score: score}
	if out.Severity == "" {
		out.Severity = scoring.Severity(score)
	}
	if e.Provider == nil || score < e.Threshold {
		return out
	}
	now := time.Now()
	if e.Now != nil {
		now = e.Now()
	}
	prompt, hash := llm.BuildPromptLanguage(c.Prompt, e.InternalCIDRs, e.Language)
	started := now
	r, err := e.Provider.Complete(ctx, llm.Request{Model: e.Model, Prompt: prompt, MaxTokens: 800})
	out.Trace = Trace{Provider: e.Provider.Name(), PromptHash: hash, Model: e.Model, Used: true, LatencyMS: time.Since(started).Milliseconds()}
	if err != nil {
		out.Trace.Error = err.Error()
		return out
	}
	out.Summary = r.Summary
	out.Actions = r.Actions
	out.FPProbability = r.FPProbability
	if rank(r.Severity) > rank(out.Severity) && r.Severity != "" {
		out.Severity = r.Severity
	}
	if rank(r.Severity) < rank(out.Severity) && r.FPProbability >= .7 {
		out.Severity = r.Severity
	}
	return out
}
func rank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}
