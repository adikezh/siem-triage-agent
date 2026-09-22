package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Request struct {
	Model     string `json:"model"`
	Prompt    string `json:"prompt"`
	MaxTokens int    `json:"max_tokens,omitempty"`
}
type Response struct {
	Severity      string   `json:"severity"`
	Summary       string   `json:"summary"`
	Actions       []string `json:"actions"`
	FPProbability float64  `json:"fp_probability"`
}
type Provider interface {
	Complete(context.Context, Request) (Response, error)
	Name() string
}

type OpenAICompatible struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
}

func (p OpenAICompatible) Name() string { return "openai-compatible" }
func (p OpenAICompatible) Complete(ctx context.Context, req Request) (Response, error) {
	if p.BaseURL == "" {
		return Response{}, fmt.Errorf("llm base URL is required")
	}
	if req.Model == "" {
		return Response{}, fmt.Errorf("llm model is required")
	}
	c := p.HTTPClient
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	body := map[string]any{"model": req.Model, "messages": []map[string]string{{"role": "user", "content": req.Prompt}}, "temperature": 0, "response_format": map[string]string{"type": "json_object"}}
	b, _ := json.Marshal(body)
	r, e := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(p.BaseURL, "/")+"/chat/completions", bytes.NewReader(b))
	if e != nil {
		return Response{}, e
	}
	r.Header.Set("content-type", "application/json")
	if p.APIKey != "" {
		r.Header.Set("authorization", "Bearer "+p.APIKey)
	}
	resp, e := c.Do(r)
	if e != nil {
		return Response{}, fmt.Errorf("llm request: %w", e)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode/100 != 2 {
		return Response{}, fmt.Errorf("llm HTTP %d", resp.StatusCode)
	}
	var envelope struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if e = json.Unmarshal(raw, &envelope); e != nil {
		return Response{}, fmt.Errorf("invalid provider envelope: %w", e)
	}
	if len(envelope.Choices) == 0 {
		return Response{}, fmt.Errorf("provider returned no choices")
	}
	var out Response
	if e = json.Unmarshal([]byte(envelope.Choices[0].Message.Content), &out); e != nil {
		return Response{}, fmt.Errorf("invalid triage JSON: %w", e)
	}
	if e = Validate(out); e != nil {
		return Response{}, e
	}
	return out, nil
}
func Validate(r Response) error {
	switch r.Severity {
	case "low", "medium", "high", "critical":
	default:
		return fmt.Errorf("invalid severity %q", r.Severity)
	}
	if r.FPProbability < 0 || r.FPProbability > 1 {
		return fmt.Errorf("fp_probability must be between 0 and 1")
	}
	for _, a := range r.Actions {
		if !allowed[a] {
			return fmt.Errorf("unsupported action %q", a)
		}
	}
	return nil
}

var allowed = map[string]bool{"investigate": true, "isolate_host": true, "block_ip": true, "open_ticket": true, "collect_evidence": true}
