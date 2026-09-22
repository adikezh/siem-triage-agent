package llm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenAICompatibleAndValidation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("authorization") != "Bearer test" {
			t.Errorf("missing auth")
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"severity\":\"high\",\"summary\":\"review\",\"actions\":[\"collect_evidence\"],\"fp_probability\":0.1}"}}]}`))
	}))
	defer srv.Close()
	p := OpenAICompatible{BaseURL: srv.URL, APIKey: "test"}
	got, e := p.Complete(context.Background(), Request{Model: "demo", Prompt: "untrusted data"})
	if e != nil {
		t.Fatal(e)
	}
	if got.Severity != "high" {
		t.Fatalf("got %#v", got)
	}
}
func TestRejectsUnsupportedAction(t *testing.T) {
	if e := Validate(Response{Severity: "high", Actions: []string{"delete_everything"}}); e == nil || !strings.Contains(e.Error(), "unsupported action") {
		t.Fatalf("expected action rejection, got %v", e)
	}
}

func TestOllamaProvider(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			t.Errorf("path=%s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"message":{"content":"{\"severity\":\"medium\",\"summary\":\"ok\",\"actions\":[],\"fp_probability\":0.2}"}}`))
	}))
	defer srv.Close()
	got, err := (Ollama{BaseURL: srv.URL}).Complete(context.Background(), Request{Model: "qwen", Prompt: "x"})
	if err != nil || got.Severity != "medium" {
		t.Fatalf("got=%#v err=%v", got, err)
	}
}

func TestAnthropicProvider(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "key" || r.Header.Get("anthropic-version") == "" {
			t.Error("missing Anthropic headers")
		}
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"{\"severity\":\"critical\",\"summary\":\"ok\",\"actions\":[\"investigate\"],\"fp_probability\":0.0}"}]}`))
	}))
	defer srv.Close()
	got, err := (Anthropic{BaseURL: srv.URL, APIKey: "key"}).Complete(context.Background(), Request{Model: "claude", Prompt: "x"})
	if err != nil || got.Severity != "critical" {
		t.Fatalf("got=%#v err=%v", got, err)
	}
}
