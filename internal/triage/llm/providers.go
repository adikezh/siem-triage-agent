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

type Ollama struct {
	BaseURL    string
	HTTPClient *http.Client
}

func (p Ollama) Name() string { return "ollama" }
func (p Ollama) Complete(ctx context.Context, req Request) (Response, error) {
	if p.BaseURL == "" {
		return Response{}, fmt.Errorf("ollama base URL is required")
	}
	if req.Model == "" {
		return Response{}, fmt.Errorf("llm model is required")
	}
	body, _ := json.Marshal(map[string]any{"model": req.Model, "messages": []map[string]string{{"role": "user", "content": req.Prompt}}, "stream": false, "format": "json", "options": map[string]any{"temperature": 0}})
	return completeJSON(ctx, p.HTTPClient, strings.TrimRight(p.BaseURL, "/")+"/api/chat", body, "ollama", func(raw []byte) (string, error) {
		var x struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		}
		if err := json.Unmarshal(raw, &x); err != nil {
			return "", err
		}
		return x.Message.Content, nil
	})
}

type Anthropic struct {
	BaseURL, APIKey string
	HTTPClient      *http.Client
}

func (p Anthropic) Name() string { return "anthropic" }
func (p Anthropic) Complete(ctx context.Context, req Request) (Response, error) {
	if p.BaseURL == "" {
		return Response{}, fmt.Errorf("anthropic base URL is required")
	}
	if p.APIKey == "" {
		return Response{}, fmt.Errorf("anthropic API key is required")
	}
	if req.Model == "" {
		return Response{}, fmt.Errorf("llm model is required")
	}
	body, _ := json.Marshal(map[string]any{"model": req.Model, "max_tokens": req.MaxTokens, "temperature": 0, "messages": []map[string]string{{"role": "user", "content": req.Prompt}}})
	return completeJSONWithHeaders(ctx, p.HTTPClient, strings.TrimRight(p.BaseURL, "/")+"/v1/messages", body, "anthropic", map[string]string{"x-api-key": p.APIKey, "anthropic-version": "2023-06-01"}, func(raw []byte) (string, error) {
		var x struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.Unmarshal(raw, &x); err != nil {
			return "", err
		}
		for _, b := range x.Content {
			if b.Text != "" {
				return b.Text, nil
			}
		}
		return "", fmt.Errorf("provider returned no content")
	})
}

func completeJSON(ctx context.Context, client *http.Client, endpoint string, body []byte, name string, extract func([]byte) (string, error)) (Response, error) {
	return completeJSONWithHeaders(ctx, client, endpoint, body, name, nil, extract)
}
func completeJSONWithHeaders(ctx context.Context, client *http.Client, endpoint string, body []byte, name string, headers map[string]string, extract func([]byte) (string, error)) (Response, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Response{}, err
	}
	r.Header.Set("content-type", "application/json")
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	resp, err := client.Do(r)
	if err != nil {
		return Response{}, fmt.Errorf("%s request: %w", name, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode/100 != 2 {
		return Response{}, fmt.Errorf("%s HTTP %d", name, resp.StatusCode)
	}
	content, err := extract(raw)
	if err != nil {
		return Response{}, fmt.Errorf("invalid %s envelope: %w", name, err)
	}
	var out Response
	if err = json.Unmarshal([]byte(content), &out); err != nil {
		return Response{}, fmt.Errorf("invalid triage JSON: %w", err)
	}
	if err = Validate(out); err != nil {
		return Response{}, err
	}
	return out, nil
}
